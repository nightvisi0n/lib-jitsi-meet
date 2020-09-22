/* global __filename, Olm */

import base64js from 'base64-js';
import { getLogger } from 'jitsi-meet-logger';
import isEqual from 'lodash.isequal';
import { v4 as uuidv4 } from 'uuid';

import * as JitsiConferenceEvents from '../../JitsiConferenceEvents';
import Deferred from '../util/Deferred';
import Listenable from '../util/Listenable';
import { JITSI_MEET_MUC_TYPE } from '../xmpp/xmpp';

import { generateSas } from './SAS';

const logger = getLogger(__filename);

const REQ_TIMEOUT = 5 * 1000;
const OLM_MESSAGE_TYPE = 'olm';
const OLM_MESSAGE_TYPES = {
    ERROR: 'error',
    KEY_INFO: 'key-info',
    KEY_INFO_ACK: 'key-info-ack',
    SAS_INIT: 'sas-init',
    SAS_ACK: 'sas-ack',
    SAS_MAC: 'sas-mac',
    SAS_DONE: 'sas-done',
    SESSION_ACK: 'session-ack',
    SESSION_INIT: 'session-init'
};
const OLM_KEY_VERIFICATION_MAC_INFO = 'Jitsi-KEY_VERIFICATION_MAC';
const OLM_KEY_VERIFICATION_MAC_KEY_IDS = 'Jitsi-KEY_IDS';
const OLM_SAS_EXTRA_INFO = 'Jitsi-SAS';
const OLM_SAS_NUM_BYTES = 6;

const kOlmData = Symbol('OlmData');

const OlmAdapterEvents = {
    OLM_ID_KEYS_READY: 'olm.id_keys_ready',
    PARTICIPANT_E2EE_CHANNEL_READY: 'olm.participant_e2ee_channel_ready',
    PARTICIPANT_SAS_READY: 'olm.participant_sas_ready',
    PARTICIPANT_KEY_UPDATED: 'olm.partitipant_key_updated'
};

/**
 * This class implements an End-to-End Encrypted communication channel between every two peers
 * in the conference. This channel uses libolm to achieve E2EE.
 *
 * The created channel is then used to exchange the secret key that each participant will use
 * to encrypt the actual media (see {@link E2EEContext}).
 *
 * A simple JSON message based protocol is implemented, which follows a request - response model:
 * - session-init: Initiates an olm session establishment procedure. This message will be sent
 *                 by the participant who just joined, to everyone else.
 * - session-ack: Completes the olm session etablishment. This messsage may contain ancilliary
 *                encrypted data, more specifically the sender's current key.
 * - key-info: Includes the sender's most up to date key information.
 * - key-info-ack: Acknowledges the reception of a key-info request. In addition, it may contain
 *                 the sender's key information, if available.
 * - error: Indicates a request processing error has occurred.
 *
 * These requessts and responses are transport independent. Currently they are sent using XMPP
 * MUC private messages.
 */
export class OlmAdapter extends Listenable {
    /**
     * Creates an adapter instance for the given conference.
     */
    constructor(conference) {
        super();

        this._conf = conference;
        this._init = new Deferred();
        this._key = undefined;
        this._keyIndex = -1;
        this._reqs = new Map();

        if (OlmAdapter.isSupported()) {
            this._bootstrapOlm();

            this._conf.on(JitsiConferenceEvents.ENDPOINT_MESSAGE_RECEIVED, this._onEndpointMessageReceived.bind(this));
            this._conf.on(JitsiConferenceEvents.CONFERENCE_JOINED, this._onConferenceJoined.bind(this));
            this._conf.on(JitsiConferenceEvents.CONFERENCE_LEFT, this._onConferenceLeft.bind(this));
            this._conf.on(JitsiConferenceEvents.USER_LEFT, this._onParticipantLeft.bind(this));
        } else {
            this._init.reject(new Error('Olm not supported'));
        }
    }

    /**
     * Indicates if olm is supported on the current platform.
     *
     * @returns {boolean}
     */
    static isSupported() {
        return typeof window.Olm !== 'undefined';
    }

    /**
     * Returns the current participants conference ID.
     *
     * @returns {string}
     */
    get myId() {
        return this._conf.myUserId();
    }

    /**
     * Updates the current participant key and distributes it to all participants in the conference
     * by sending a key-info message.
     *
     * @param {Uint8Array|boolean} key - The new key.
     * @returns {number}
     */
    async updateCurrentKey(key) {
        this._key = key;

        return this._keyIndex;
    }

    /**
     * Updates the current participant key and distributes it to all participants in the conference
     * by sending a key-info message.
     *
     * @param {Uint8Array|boolean} key - The new key.
     * @retrns {Promise<Number>}
     */
    async updateKey(key) {
        // Store it locally for new sessions.
        this._key = key;
        this._keyIndex++;

        // Broadcast it.
        const promises = [];

        for (const participant of this._conf.getParticipants()) {
            const pId = participant.getId();
            const olmData = this._getParticipantOlmData(participant);

            // Skip participants without support for E2EE.
            if (!participant.getProperty('features_e2ee')) {
                // eslint-disable-next-line no-continue
                continue;
            }

            if (!olmData.session) {
                logger.warn(`Tried to send key to participant ${pId} but we have no session`);

                // eslint-disable-next-line no-continue
                continue;
            }

            const uuid = uuidv4();
            const data = {
                [JITSI_MEET_MUC_TYPE]: OLM_MESSAGE_TYPE,
                olm: {
                    type: OLM_MESSAGE_TYPES.KEY_INFO,
                    data: {
                        ciphertext: this._encryptKeyInfo(olmData.session),
                        uuid
                    }
                }
            };
            const d = new Deferred();

            d.setRejectTimeout(REQ_TIMEOUT);
            d.catch(() => {
                this._reqs.delete(uuid);
            });
            this._reqs.set(uuid, d);
            promises.push(d);

            this._sendMessage(data, pId);
        }

        await Promise.allSettled(promises);

        // TODO: retry failed ones?

        return this._keyIndex;
    }

    /**
     * Mark the SAS as verified for the given participant.
     *
     * @param {JitsiParticipant} participant - The target participant.
     * @returns {void}
     */
    sasVerified(participant) {
        const olmData = this._getParticipantOlmData(participant);

        if (olmData.sas && olmData.sas.is_their_key_set() && !olmData.sasMacSent) {
            this._sendSasMac(participant);

            // Mark the MAC as sent so we don't send it multiple times.
            olmData.sasMacSent = true;

            return;
        }

        logger.warn('Cannot mark SAS verified');
    }

    /**
     * Starts the verification process for the given participant.
     *
     * @param {JitsiParticipant} participant - The target participant.
     * @returns {Promise<void>}
     * @private
     */
    async startVerification(participant) {
        const pId = participant.getId();
        const olmData = this._getParticipantOlmData(participant);

        if (!olmData.session) {
            logger.warn(`Tried to start verification with participant ${pId} but we have no session`);

            return;
        }

        if (!olmData.sas) {
            olmData.sas = new Olm.SAS();

            const data = {
                [JITSI_MEET_MUC_TYPE]: OLM_MESSAGE_TYPE,
                olm: {
                    type: OLM_MESSAGE_TYPES.SAS_INIT,
                    data: {
                        // TODO: send a commitment first.
                        key: olmData.sas.get_pubkey(),
                        uuid: uuidv4
                    }
                }
            };

            this._sendMessage(data, pId);

            // TODO: handle failures. Reschedule?
        }
    }

    /**
     * Internal helper to bootstrap the olm library.
     *
     * @returns {Promise<void>}
     * @private
     */
    async _bootstrapOlm() {
        logger.debug('Initializing Olm...');

        try {
            await Olm.init();

            this._olmAccount = new Olm.Account();
            this._olmAccount.create();

            // Store the Olm ID keys. There are 2 of them:
            //  - curve25519: identity key pair.
            //  - ed25519: fingerprint key pair.
            this._idKeys = JSON.parse(this._olmAccount.identity_keys());

            logger.debug(`Olm ${Olm.get_library_version().join('.')} initialized`);
            this._init.resolve();
            this.eventEmitter.emit(OlmAdapterEvents.OLM_ID_KEYS_READY, this._idKeys);
        } catch (e) {
            logger.error('Failed to initialize Olm', e);
            this._init.reject(e);
        }
    }

    /**
     * Internal helper for encrypting the current key information for a given participant.
     *
     * @param {Olm.Session} session - Participant's session.
     * @returns {string} - The encrypted text with the key information.
     * @private
     */
    _encryptKeyInfo(session) {
        const keyInfo = {};

        if (this._key !== undefined) {
            keyInfo.key = this._key ? base64js.fromByteArray(this._key) : false;
            keyInfo.keyIndex = this._keyIndex;
        }

        return session.encrypt(JSON.stringify(keyInfo));
    }

    /**
     * Internal helper for getting the olm related data associated with a participant.
     *
     * @param {JitsiParticipant} participant - Participant whose data wants to be extracted.
     * @returns {Object}
     * @private
     */
    _getParticipantOlmData(participant) {
        participant[kOlmData] = participant[kOlmData] || {};

        return participant[kOlmData];
    }

    /**
     * Handles the conference joined event. Upon joining a conference, the participant
     * who just joined will start new olm sessions with every other participant.
     *
     * @private
     */
    async _onConferenceJoined() {
        logger.debug('Conference joined');

        await this._init;

        const promises = [];

        // Establish a 1-to-1 Olm session with every participant in the conference.
        // We are forcing the last user to join the conference to start the exchange
        // so we can send some pre-established secrets in the ACK.
        for (const participant of this._conf.getParticipants()) {
            // Don't skip any participant since we might not have received their features yet.
            promises.push(this._sendSessionInit(participant));
        }

        await Promise.allSettled(promises);

        // TODO: retry failed ones.
    }

    /**
     * Handles leaving the conference, cleaning up olm sessions.
     *
     * @private
     */
    async _onConferenceLeft() {
        logger.debug('Conference left');

        await this._init;

        for (const participant of this._conf.getParticipants()) {
            this._onParticipantLeft(participant.getId(), participant);
        }

        if (this._olmAccount) {
            this._olmAccount.free();
            this._olmAccount = undefined;
        }
    }

    /**
     * Main message handler. Handles 1-to-1 messages received from other participants
     * and send the appropriate replies.
     *
     * @private
     */
    async _onEndpointMessageReceived(participant, payload) {
        if (payload[JITSI_MEET_MUC_TYPE] !== OLM_MESSAGE_TYPE) {
            return;
        }

        if (!payload.olm) {
            logger.warn('Incorrectly formatted message');

            return;
        }

        await this._init;

        const msg = payload.olm;
        const pId = participant.getId();
        const olmData = this._getParticipantOlmData(participant);

        switch (msg.type) {
        case OLM_MESSAGE_TYPES.SESSION_INIT: {
            if (olmData.session) {
                logger.warn(`Participant ${pId} already has a session`);

                this._sendError(participant, 'Session already established');
            } else {
                // Create a session for communicating with this participant.

                const session = new Olm.Session();

                session.create_outbound(this._olmAccount, msg.data.idKey, msg.data.otKey);
                olmData.session = session;

                // Send ACK
                const ack = {
                    [JITSI_MEET_MUC_TYPE]: OLM_MESSAGE_TYPE,
                    olm: {
                        type: OLM_MESSAGE_TYPES.SESSION_ACK,
                        data: {
                            ciphertext: this._encryptKeyInfo(session),
                            uuid: msg.data.uuid
                        }
                    }
                };

                this._sendMessage(ack, pId);

                this.eventEmitter.emit(OlmAdapterEvents.PARTICIPANT_E2EE_CHANNEL_READY, pId);
            }
            break;
        }
        case OLM_MESSAGE_TYPES.SESSION_ACK: {
            if (olmData.session) {
                logger.warn(`Participant ${pId} already has a session`);

                this._sendError(participant, 'No session found');
            } else if (msg.data.uuid === olmData.pendingSessionUuid) {
                const { ciphertext } = msg.data;
                const d = this._reqs.get(msg.data.uuid);
                const session = new Olm.Session();

                session.create_inbound(this._olmAccount, ciphertext.body);

                // Remove OT keys that have been used to setup this session.
                this._olmAccount.remove_one_time_keys(session);

                // Decrypt first message.
                const data = session.decrypt(ciphertext.type, ciphertext.body);

                olmData.session = session;
                olmData.pendingSessionUuid = undefined;

                this.eventEmitter.emit(OlmAdapterEvents.PARTICIPANT_E2EE_CHANNEL_READY, pId);

                this._reqs.delete(msg.data.uuid);
                d.resolve();

                const json = safeJsonParse(data);

                if (json.key) {
                    const key = base64js.toByteArray(json.key);
                    const keyIndex = json.keyIndex;

                    olmData.lastKey = key;
                    this.eventEmitter.emit(OlmAdapterEvents.PARTICIPANT_KEY_UPDATED, pId, key, keyIndex);
                }
            } else {
                logger.warn('Received ACK with the wrong UUID');

                this._sendError(participant, 'Invalid UUID');
            }
            break;
        }
        case OLM_MESSAGE_TYPES.ERROR: {
            logger.error(msg.data.error);

            break;
        }
        case OLM_MESSAGE_TYPES.KEY_INFO: {
            if (olmData.session) {
                const { ciphertext } = msg.data;
                const data = olmData.session.decrypt(ciphertext.type, ciphertext.body);
                const json = safeJsonParse(data);

                if (json.key !== undefined && json.keyIndex !== undefined) {
                    const key = json.key ? base64js.toByteArray(json.key) : false;
                    const keyIndex = json.keyIndex;

                    if (!isEqual(olmData.lastKey, key)) {
                        olmData.lastKey = key;
                        this.eventEmitter.emit(OlmAdapterEvents.PARTICIPANT_KEY_UPDATED, pId, key, keyIndex);
                    }

                    // Send ACK.
                    const ack = {
                        [JITSI_MEET_MUC_TYPE]: OLM_MESSAGE_TYPE,
                        olm: {
                            type: OLM_MESSAGE_TYPES.KEY_INFO_ACK,
                            data: {
                                ciphertext: this._encryptKeyInfo(olmData.session),
                                uuid: msg.data.uuid
                            }
                        }
                    };

                    this._sendMessage(ack, pId);
                }
            } else {
                logger.debug(`Received key info message from ${pId} but we have no session for them!`);

                this._sendError(participant, 'No session found while processing key-info');
            }
            break;
        }
        case OLM_MESSAGE_TYPES.KEY_INFO_ACK: {
            if (olmData.session) {
                const { ciphertext } = msg.data;
                const data = olmData.session.decrypt(ciphertext.type, ciphertext.body);
                const json = safeJsonParse(data);

                if (json.key !== undefined && json.keyIndex !== undefined) {
                    const key = json.key ? base64js.toByteArray(json.key) : false;
                    const keyIndex = json.keyIndex;

                    if (!isEqual(olmData.lastKey, key)) {
                        olmData.lastKey = key;
                        this.eventEmitter.emit(OlmAdapterEvents.PARTICIPANT_KEY_UPDATED, pId, key, keyIndex);
                    }
                }

                const d = this._reqs.get(msg.data.uuid);

                this._reqs.delete(msg.data.uuid);
                d.resolve();
            } else {
                logger.debug(`Received key info ack message from ${pId} but we have no session for them!`);

                this._sendError(participant, 'No session found while processing key-info-ack');
            }
            break;
        }
        case OLM_MESSAGE_TYPES.SAS_INIT: {
            if (olmData.session) {
                if (olmData.sas) {
                    logger.warn(`SAS already created for participant ${pId}`);

                    return;
                }

                const { key, uuid } = msg.data;

                olmData.sas = new Olm.SAS();
                olmData.sas.set_their_key(key);

                // Build SAS info: <token>|<starting participant ID>-<other participant ID>-<transaction ID>
                const info = `${OLM_SAS_EXTRA_INFO}|${pId}-${this.myId}-${uuid}`;

                const sasBytes = olmData.sas.generate_bytes(info, OLM_SAS_NUM_BYTES);
                const sas = generateSas(sasBytes);

                this.eventEmitter.emit(OlmAdapterEvents.PARTICIPANT_SAS_READY, pId, sas);

                // Send ACK.
                const ack = {
                    [JITSI_MEET_MUC_TYPE]: OLM_MESSAGE_TYPE,
                    olm: {
                        type: OLM_MESSAGE_TYPES.SAS_ACK,
                        data: {
                            key: olmData.sas.get_pubkey(),
                            uuid
                        }
                    }
                };

                this._sendMessage(ack, pId);
            } else {
                logger.debug(`Received sas init message from ${pId} but we have no session for them!`);

                this._sendError(participant, 'No session found while processing sas-init');
            }
            break;
        }
        case OLM_MESSAGE_TYPES.SAS_ACK: {
            if (olmData.session) {
                if (!olmData.sas) {
                    logger.warn(`SAS already created for participant ${pId}`);

                    return;
                }

                const { key, uuid } = msg.data;

                if (olmData.sas.is_their_key_set()) {
                    logger.warn('SAS already has their key!');

                    return;
                }

                olmData.sas.set_their_key(key);

                // Build SAS info: <token>|<starting participant ID>-<other participant ID>-<transaction ID>
                const info = `${OLM_SAS_EXTRA_INFO}|${this.myId}-${pId}-${uuid}`;

                const sasBytes = olmData.sas.generate_bytes(info, OLM_SAS_NUM_BYTES);
                const sas = generateSas(sasBytes);

                this.eventEmitter.emit(OlmAdapterEvents.PARTICIPANT_SAS_READY, pId, sas);
            } else {
                logger.debug(`Received sas ack message from ${pId} but we have no session for them!`);

                this._sendError(participant, 'No session found while processing sas-ack');
            }
            break;
        }
        case OLM_MESSAGE_TYPES.SAS_MAC: {
            if (olmData.session) {
                if (!olmData.sas) {
                    logger.warn(`SAS already created for participant ${pId}`);

                    return;
                }

                const { keys, mac, uuid } = msg.data;

                if (!mac || !keys) {
                    logger.warn('Invalid SAS MAC message');

                    return;
                }

                // Verify the received MACs.

                const baseInfo = `${OLM_KEY_VERIFICATION_MAC_INFO}${pId}${this.myId}${uuid}`;
                const keysMac = olmData.sas.calculate_mac(
                    Object.keys(mac).sort().join(','), // eslint-disable-line newline-per-chained-call
                    baseInfo + OLM_KEY_VERIFICATION_MAC_KEY_IDS,
                );

                if (keysMac !== keys) {
                    logger.error('SAS verification error: keys MAC mismatch');

                    // TODO: emit event.
                    return;
                }

                for (const [ keyInfo, computedMac ] of Object.entries(mac)) {
                    const keyType = keyInfo.split(':')[0];
                    const pubKey = participant.getProperty(`e2ee.idKey.${keyType}`);

                    if (!pubKey) {
                        logger.warn(`Could not get ${keyType} public key for participant ${pId}`);

                        return;
                    }

                    const ourComputedMac = olmData.sas.calculate_mac(
                        pubKey,
                        baseInfo + keyInfo
                    );

                    if (computedMac !== ourComputedMac) {
                        logger.error('SAS verification error: MAC mismatch');

                        return;
                    }
                }

                // At this point all MACs are verified, so we can mark the user as verified.
                // We'll now send our own MACs.
                if (!olmData.sasMacSent) {
                    this._sendSasMac(participant);
                    olmData.sasMacSent = true;
                }

                this.eventEmitter.emit(OlmAdapterEvents.OLM_SAS_VERIFIED, pId);
                logger.info(`SAS MAC verified for participant ${pId}`);
            } else {
                logger.debug(`Received sas mac message from ${pId} but we have no session for them!`);

                this._sendError(participant, 'No session found while processing sas-ack');
            }
            break;
        }
        default: {
            logger.error(`Unknown message type: ${msg.type}`);
            break;
        }
        }

    }

    /**
     * Handles a participant leaving. When a participant leaves their olm session is destroyed.
     *
     * @private
     */
    _onParticipantLeft(id, participant) {
        logger.debug(`Participant ${id} left`);

        const olmData = this._getParticipantOlmData(participant);

        if (olmData.session) {
            olmData.session.free();
            olmData.session = undefined;
        }

        if (olmData.sas) {
            olmData.sas.free();
            olmData.sas = undefined;
        }
    }

    /**
     * Builds and sends an error message to the target participant.
     *
     * @param {JitsiParticipant} participant - The target participant.
     * @param {string} error - The error message.
     * @returns {void}
     */
    _sendError(participant, error) {
        const pId = participant.getId();
        const err = {
            [JITSI_MEET_MUC_TYPE]: OLM_MESSAGE_TYPE,
            olm: {
                type: OLM_MESSAGE_TYPES.ERROR,
                data: {
                    error
                }
            }
        };

        this._sendMessage(err, pId);
    }

    /**
     * Internal helper to send the given object to the given participant ID.
     * This function merely exists so the transport can be easily swapped.
     * Currently messages are transmitted via XMPP MUC private messages.
     *
     * @param {object} data - The data that will be sent to the target participant.
     * @param {string} participantId - ID of the target participant.
     */
    _sendMessage(data, participantId) {
        this._conf.sendMessage(data, participantId);
    }

    /**
     * Builds and sends the SAS MAC message to the given participant.
     */
    _sendSasMac(participant) {
        const pId = participant.getId();
        const olmData = this._getParticipantOlmData(participant);
        const uuid = uuidv4();

        // Calculate and send MAC with the keys to be verified.
        const mac = {};
        const keyList = [];
        const baseInfo = `${OLM_KEY_VERIFICATION_MAC_INFO}${this.myId}${pId}${uuid}`;
        const deviceKeyId = `ed25519:${this.myId}`;

        mac[deviceKeyId] = olmData.sas.calculate_mac(
            this._idKeys.ed25519,
            baseInfo + deviceKeyId);
        keyList.push(deviceKeyId);

        const keys = olmData.sas.calculate_mac(
            keyList.sort().join(','),
            baseInfo + OLM_KEY_VERIFICATION_MAC_KEY_IDS,
        );

        const data = {
            [JITSI_MEET_MUC_TYPE]: OLM_MESSAGE_TYPE,
            olm: {
                type: OLM_MESSAGE_TYPES.SAS_MAC,
                data: {
                    keys,
                    mac,
                    uuid
                }
            }
        };

        this._sendMessage(data, pId);
    }

    /**
     * Builds and sends the session-init request to the target participant.
     *
     * @param {JitsiParticipant} participant - Participant to whom we'll send the request.
     * @returns {Promise} - The promise will be resolved when the session-ack is received.
     * @private
     */
    _sendSessionInit(participant) {
        const pId = participant.getId();
        const olmData = this._getParticipantOlmData(participant);

        if (olmData.session) {
            logger.warn(`Tried to send session-init to ${pId} but we already have a session`);

            return Promise.reject();
        }

        if (olmData.pendingSessionUuid !== undefined) {
            logger.warn(`Tried to send session-init to ${pId} but we already have a pending session`);

            return Promise.reject();
        }

        // Generate a One Time Key.
        this._olmAccount.generate_one_time_keys(1);

        const otKeys = JSON.parse(this._olmAccount.one_time_keys());
        const otKey = Object.values(otKeys.curve25519)[0];

        if (!otKey) {
            return Promise.reject(new Error('No one-time-keys generated'));
        }

        // Mark the OT keys (one really) as published so they are not reused.
        this._olmAccount.mark_keys_as_published();

        const uuid = uuidv4();
        const init = {
            [JITSI_MEET_MUC_TYPE]: OLM_MESSAGE_TYPE,
            olm: {
                type: OLM_MESSAGE_TYPES.SESSION_INIT,
                data: {
                    idKey: this._idKeys.curve25519,
                    otKey,
                    uuid
                }
            }
        };

        const d = new Deferred();

        d.setRejectTimeout(REQ_TIMEOUT);
        d.catch(() => {
            this._reqs.delete(uuid);
            olmData.pendingSessionUuid = undefined;
        });
        this._reqs.set(uuid, d);

        this._sendMessage(init, pId);

        // Store the UUID for matching with the ACK.
        olmData.pendingSessionUuid = uuid;

        return d;
    }
}

OlmAdapter.events = OlmAdapterEvents;

/**
 * Helper to ensure JSON parsing always returns an object.
 *
 * @param {string} data - The data that needs to be parsed.
 * @returns {object} - Parsed data or empty object in case of failure.
 */
function safeJsonParse(data) {
    try {
        return JSON.parse(data);
    } catch (e) {
        return {};
    }
}
