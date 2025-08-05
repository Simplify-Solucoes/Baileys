import type { proto } from '../../WAProto/index.js'
import type { BinaryNode } from '../WABinary'
import type { AuthenticationState, MessageRelayOptions } from '../Types'
import { isJidGroup, jidDecode } from '../WABinary'

export type SendMessagesAgainDeps = {
    getMessage: (key: proto.IMessageKey) => Promise<proto.IMessage | undefined>
    assertSessions: (jids: string[], force: boolean) => Promise<boolean>
    authState: AuthenticationState
    relayMessage: (jid: string, message: proto.IMessage, options: MessageRelayOptions) => Promise<string>
    updateSendMessageAgainCount: (id: string, participant: string) => void
    logger: any
}

export const sendMessagesAgain = async (
    key: proto.IMessageKey,
    ids: string[],
    retryNode: BinaryNode,
    deps: SendMessagesAgainDeps
) => {
    const { getMessage, assertSessions, authState, relayMessage, updateSendMessageAgainCount, logger } = deps
    
    // Cache implemented in makeMessagesSocket - getMessage now checks cache first
    const msgs = await Promise.all(ids.map(id => getMessage({ ...key, id })))
    const remoteJid = key.remoteJid!
    const participant = key.participant || remoteJid
    // if it's the primary jid sending the request
    // just re-send the message to everyone
    // prevents the first message decryption failure
    const sendToAll = !jidDecode(participant)?.device
    await assertSessions([participant], true)

    if (isJidGroup(remoteJid)) {
        await authState.keys.set({ 'sender-key-memory': { [remoteJid]: null } })
    }

    logger.debug({ participant, sendToAll }, 'forced new session for retry recp')

    for (const [i, msg] of msgs.entries()) {
        if (msg) {
            updateSendMessageAgainCount(ids[i]!, participant)
            const msgRelayOpts: MessageRelayOptions = { messageId: ids[i] }

            if (sendToAll) {
                msgRelayOpts.useUserDevicesCache = false
            } else {
                msgRelayOpts.participant = {
                    jid: participant,
                    count: +retryNode.attrs.count!
                }
            }

            await relayMessage(key.remoteJid!, msg, msgRelayOpts)
        } else {
            logger.debug({ jid: key.remoteJid, id: ids[i] }, 'recv retry request, but message not available')
        }
    }
}