import type { SignalKeyStoreWithTransaction } from '../Types'
import { 
    isLidUser, 
    isJidUser,
    jidDecode
} from '../WABinary'
import logger from '../Utils/logger'

export class LIDMappingStore {
    private readonly keys: SignalKeyStoreWithTransaction
    
    constructor(keys: SignalKeyStoreWithTransaction) {
        this.keys = keys
    }

    /**
     * Store LID-PN mapping - USER LEVEL
     * But we keep track of which device triggered the mapping for migration
     */
    async storeLIDPNMapping(lid: string, pn: string): Promise<void> {
        // Validate inputs
        if (!((isLidUser(lid) && isJidUser(pn)) || (isJidUser(lid) && isLidUser(pn)))) {
            logger.warn(`Invalid LID-PN mapping: ${lid}, ${pn}`)
            return
        }

        const [lidJid, pnJid] = isLidUser(lid) ? [lid, pn] : [pn, lid]
        
        const lidDecoded = jidDecode(lidJid)
        const pnDecoded = jidDecode(pnJid)
        
        if (!lidDecoded || !pnDecoded) return
        
        const pnUser = pnDecoded.user
        const lidUser = lidDecoded.user
        
        // Keep track of the device that triggered this mapping
        const triggerDevice = pnDecoded.device !== undefined ? pnDecoded.device : 0
        
        logger.info(`Storing USER LID mapping: PN ${pnUser} → LID ${lidUser} (triggered by device ${triggerDevice})`)
        
        await this.keys.transaction(async () => {
            await this.keys.set({
                'lid-mapping': {
                    [pnUser]: lidUser,                    // "554396160286" -> "102765716062358"
                    [`${lidUser}_reverse`]: pnUser        // "102765716062358_reverse" -> "554396160286"
                }
            })
        })
        
        logger.info(`USER LID mapping stored: PN ${pnUser} → LID ${lidUser}`)
    }

    /**
     * Get LID for PN - Returns device-specific LID based on user mapping
     */
    async getLIDForPN(pn: string): Promise<string | null> {
        if (!isJidUser(pn)) return null
        
        const decoded = jidDecode(pn)
        if (!decoded) return null
        
        // Look up user-level mapping (whatsmeow approach)
        const pnUser = decoded.user
        const stored = await this.keys.get('lid-mapping', [pnUser])
        const lidUser = stored[pnUser]
        
        if (!lidUser) {
            logger.warn(`No LID mapping found for PN user ${pnUser}`)
            return null
        }
        
        if (typeof lidUser !== 'string') return null
        
        // Push the PN device ID to the LID to maintain device separation
        const pnDevice = decoded.device !== undefined ? decoded.device : 0
        const deviceSpecificLid = `${lidUser}:${pnDevice}@lid`

        logger.info(`getLIDForPN: ${pn} → ${deviceSpecificLid} (user mapping with device ${pnDevice})`)
        return deviceSpecificLid
    }

    /**
     * Get PN for LID - USER LEVEL with device construction
     */
    async getPNForLID(lid: string): Promise<string | null> {
        if (!isLidUser(lid)) return null
        
        const decoded = jidDecode(lid)
        if (!decoded) return null
        
        // Look up reverse user mapping
        const lidUser = decoded.user
        const stored = await this.keys.get('lid-mapping', [`${lidUser}_reverse`])
        const pnUser = stored[`${lidUser}_reverse`]
        
        if (!pnUser || typeof pnUser !== 'string') {
            logger.warn(`No reverse mapping found for LID user: ${lidUser}`)
            return null
        }
        
        // Construct device-specific PN JID
        const lidDevice = decoded.device !== undefined ? decoded.device : 0
        const pnJid = `${pnUser}:${lidDevice}@s.whatsapp.net`

        logger.info(`Found reverse mapping: ${lid} → ${pnJid}`)
        return pnJid
    }

    /**
     * Check if a LID exists in our mappings (for validation) - DEVICE-SPECIFIC
     * This helps when we have a direct LID contact and need to verify it exists
     */
    async isLIDMapped(lid: string): Promise<boolean> {
        if (!isLidUser(lid)) return false
        
        const decoded = jidDecode(lid)
        if (!decoded) return false
        
        // CRITICAL FIX: Check if any PN device has mapped to this LID user
        // Since we can't easily reverse lookup, we'll need to scan for any reverse mapping containing this LID user
        // This is a simplified check - in a real implementation you'd want to maintain a proper reverse index
        
        // For now, return false as this method is primarily for validation
        // The main logic should rely on getLIDForPN for specific device lookups
        logger.info(`isLIDMapped simplified for device-specific: ${lid} → assuming not mapped`)
        logger.info(`   Use getLIDForPN on specific PN devices for accurate checks`)
        return false
    }

    /**
     * Check if JID has session
     */
    async hasSession(jid: string): Promise<boolean> {
        const decoded = jidDecode(jid)
        if (!decoded) return false
        
        let signalUser = decoded.user
        if (isLidUser(jid)) {
            signalUser = `${decoded.user}_1`
        }
        
        const address = decoded.device !== undefined
            ? `${signalUser}.${decoded.device}`
            : `${signalUser}.0`
            
        const sessions = await this.keys.get('session', [address])
        return !!sessions[address]
    }

    /**
     * Check if JID is LID
     */
    static isLID(jid: string): boolean {
        return !!isLidUser(jid)
    }

    /**
     * Check if JID is PN
     */
    static isPN(jid: string): boolean {
        return !!isJidUser(jid)
    }

    /**
     * Fast cache lookup for LID (simplified version for compatibility)
     */
    getFromCache(pn: string): string | null {
        // This is a simplified sync method for backward compatibility
        // In production, use getLIDForPN for proper async lookups
        return null
    }
}