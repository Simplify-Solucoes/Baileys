import type { SignalRepository } from '../Types'
import type { ILogger } from './logger'
import { isJidUser, isLidUser } from '../WABinary'

/**
 * Apply WhatsApp's LID priority system to determine encryption identity
 * Based on whatsmeow's message.go:284-298
 * WHATSMEOW APPROACH: Always migrate when using LID, no session checks
 */
export async function determineLIDEncryptionJid(
    sender: string,
    senderAlt: string | undefined,
    repository: SignalRepository,
    logger: ILogger,
    meId?: string
): Promise<{ encryptionJid: string; shouldMigrate: boolean }> {
    // Default to original sender
    let encryptionJid = sender
    let shouldMigrate = false

    // Skip LID logic for non-user JIDs or bots (matching whatsmeow)
    if (!isJidUser(sender) || sender.includes('bot')) {
        return { encryptionJid, shouldMigrate }
    }

    // WHATSMEOW APPROACH: Simple priority without session checks
    
    // PRIORITY 1: Use LID from message metadata (info.SenderAlt)
    if (senderAlt && isLidUser(senderAlt)) {
        logger.info({ 
            sender, 
            senderAlt, 
            deviceId: sender.split(':')[1]?.split('@')[0] || '0'
        }, 'Using LID from message metadata')
        encryptionJid = senderAlt
        shouldMigrate = true // Always migrate when switching to LID
        return { encryptionJid, shouldMigrate }
    }

    // PRIORITY 2: Check stored LID mapping
    try {
        const lidStore = repository.getLIDMappingStore()
        const storedLid = await lidStore.getLIDForPN(sender)
        
        if (storedLid) {
            logger.info({ 
                sender, 
                storedLid, 
                deviceId: sender.split(':')[1]?.split('@')[0] || '0'
            }, 'Using stored LID mapping')
            encryptionJid = storedLid
            shouldMigrate = true // Always migrate when switching to LID
            return { encryptionJid, shouldMigrate }
        }
    } catch (error) {
        logger.error({ sender, error }, 'Failed to check stored LID mapping')
    }

    // DEFAULT: Use PN address for encryption (no migration needed)
    logger.debug({ 
        sender, 
        deviceId: sender.split(':')[1]?.split('@')[0] || '0'
    }, 'No LID found - using PN for encryption')
    return { encryptionJid, shouldMigrate }
}

/**
 * Handle LID migration sync messages
 * Based on whatsmeow's message.go:750-751
 */
export async function handleLIDMigrationSync(
    encodedPayload: Uint8Array,
    _repository: SignalRepository,
    logger: ILogger
): Promise<void> {
    try {
        logger.info({ payloadSize: encodedPayload.length }, 'Received LID migration sync message from server')
        
        // In a complete implementation:
        // 1. Decode proto.LIDMigrationMappingSyncPayload
        // 2. Extract pnToLidMappings array
        // 3. Store each mapping using repository.getLIDMappingStore().storeLIDPNMapping()
        // 4. Handle latestLid vs assignedLid for LID refresh
    } catch (error) {
        logger.error({ error }, 'Failed to process LID migration sync')
    }
}

/**
 * Check if we should recreate session after decryption failure
 * Based on whatsmeow's retry.go:126-137
 */
export function shouldRecreateSession(
    _jid: string,
    retryCount: number,
    hasSession: boolean,
    lastRecreationTime?: number
): { shouldRecreate: boolean; reason: string } {
    // No session exists - immediate recreation
    if (!hasSession) {
        return {
            shouldRecreate: true,
            reason: "we don't have a Signal session with them"
        }
    }

    // Need at least 2 retries before recreation
    if (retryCount < 2) {
        return {
            shouldRecreate: false,
            reason: 'retry count below threshold'
        }
    }

    // Check if enough time passed since last recreation (1 hour)
    const recreationTimeout = 60 * 60 * 1000
    if (!lastRecreationTime || Date.now() - lastRecreationTime > recreationTimeout) {
        return {
            shouldRecreate: true,
            reason: 'retry count > 1 and timeout expired'
        }
    }

    return {
        shouldRecreate: false,
        reason: 'recreation attempted recently'
    }
}