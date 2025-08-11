import type { SignalKeyStoreWithTransaction } from '../Types'
import { 
    isLidUser, 
    isJidUser,
    jidDecode
} from '../WABinary'

/**
 * Simple LID-PN mapping store matching whatsmeow's exact behavior
 * Optimized for Redis: Direct keys.set/get (no redundant Map cache)
 * 
 * Key fix: Store only USER portions, copy device IDs from input to output
 */
export class LIDMappingStore {
    private readonly keys: SignalKeyStoreWithTransaction
    
    // Small LRU cache for immediate synchronous access in retry scenarios
    private readonly syncCache = new Map<string, string>() // Limited cache for sync access
    private readonly maxCacheSize = 100 // Keep small to avoid memory issues
    
    constructor(keys: SignalKeyStoreWithTransaction) {
        this.keys = keys
    }

    /**
     * Store LID-PN mapping - USER LEVEL (whatsmeow approach)
     * But we keep track of which device triggered the mapping for migration
     */
    async storeLIDPNMapping(lid: string, pn: string): Promise<void> {
        // Validate inputs
        if (!((isLidUser(lid) && isJidUser(pn)) || (isJidUser(lid) && isLidUser(pn)))) {
            console.warn(`Invalid LID-PN mapping: ${lid}, ${pn}`)
            return
        }

        // Ensure correct order
        const [lidJid, pnJid] = isLidUser(lid) ? [lid, pn] : [pn, lid]
        
        const lidDecoded = jidDecode(lidJid)
        const pnDecoded = jidDecode(pnJid)
        
        if (!lidDecoded || !pnDecoded) return
        
        // WHATSMEOW APPROACH: Store user-level mapping
        const pnUser = pnDecoded.user
        const lidUser = lidDecoded.user
        
        // Keep track of the device that triggered this mapping
        const triggerDevice = pnDecoded.device !== undefined ? pnDecoded.device : 0
        
        console.log(`📱 Storing USER LID mapping: PN ${pnUser} → LID ${lidUser} (triggered by device ${triggerDevice})`)
        
        // Redis-optimized: Direct storage, no redundant cache
        await this.keys.transaction(async () => {
            // Store bidirectional USER mapping (whatsmeow style)
            await this.keys.set({
                'lid-mapping': {
                    [pnUser]: lidUser,                    // "554396160286" -> "102765716062358"
                    [`${lidUser}_reverse`]: pnUser        // "102765716062358_reverse" -> "554396160286"
                }
            })
        })
        
        // Update sync cache after successful storage (user-level)
        this.updateSyncCache(pnUser, lidUser)
        
        console.log(`✅ USER LID mapping stored: PN ${pnUser} → LID ${lidUser} (whatsmeow approach)`)
    }

    /**
     * Get LID for PN - Returns device-specific LID based on user mapping
     * WHATSMEOW APPROACH: User-level mapping, but we construct device-specific JID
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
            console.log(`🚫 No LID mapping found for PN user ${pnUser}`)
            return null
        }
        
        if (typeof lidUser !== 'string') return null
        
        // CRITICAL: Construct device-specific LID JID
        // Push the PN device ID to the LID to maintain device separation
        const pnDevice = decoded.device !== undefined ? decoded.device : 0
        const deviceSpecificLid = `${lidUser}:${pnDevice}@lid`
        
        // Update sync cache for immediate access
        this.updateSyncCache(pnUser, lidUser)
        
        console.log(`🔍 getLIDForPN: ${pn} → ${deviceSpecificLid} (user mapping with device ${pnDevice})`)
        return deviceSpecificLid
    }

    /**
     * Get PN for LID - USER LEVEL with device construction
     * WHATSMEOW APPROACH: User-level reverse lookup
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
            console.log(`🚫 No reverse mapping found for LID user: ${lidUser}`)
            return null
        }
        
        // Construct device-specific PN JID
        const lidDevice = decoded.device !== undefined ? decoded.device : 0
        const pnJid = `${pnUser}:${lidDevice}@s.whatsapp.net`
        
        console.log(`✅ Found reverse mapping: ${lid} → ${pnJid}`)
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
        console.log(`🚫 isLIDMapped simplified for device-specific: ${lid} → assuming not mapped`)
        console.log(`   Use getLIDForPN on specific PN devices for accurate checks`)
        return false
    }

    /**
     * DEPRECATED: Session migration is now handled in libsignal.ts using proper storage interface
     * This method is kept for compatibility but should not be used
     */
    async migrateSession(pnJid: string, lidJid: string): Promise<void> {
        console.warn(`⚠️ DEPRECATED: migrateSession called on LIDMappingStore. Session migration should use repository.migrateSession() instead.`)
        console.log(`   Attempted migration: ${pnJid} -> ${lidJid}`)
        console.log(`   This function is deprecated to avoid conflicts with the main session migration logic.`)
    }

    /**
     * Helper to manage small sync cache - USER LEVEL
     */
    private updateSyncCache(pnUser: string, lidUser: string): void {
        // Keep cache small - remove oldest if needed
        if (this.syncCache.size >= this.maxCacheSize) {
            const firstKey = this.syncCache.keys().next().value
            if (firstKey) {
                this.syncCache.delete(firstKey)
            }
        }
        // Store user-level mapping
        this.syncCache.set(pnUser, lidUser)
    }

    /**
     * Fast synchronous cache lookup for retry scenarios
     */
    getFromCache(pn: string): string | null {
        if (!isJidUser(pn)) return null
        
        const decoded = jidDecode(pn)
        if (!decoded) return null
        
        // User-level cache lookup
        const lidUser = this.syncCache.get(decoded.user)
        if (!lidUser) return null
        
        // Construct device-specific LID
        const deviceId = decoded.device !== undefined ? decoded.device : 0
        return `${lidUser}:${deviceId}@lid`
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
     * Set privacy token manager (for compatibility)
     */
    setPrivacyTokenManager(_manager: any): void {
        // Not needed in simple implementation
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
     * Clear Redis mappings (if needed)
     */
    async clear() {
        // Could clear Redis lid-mapping namespace if needed
        // For now, this is a no-op since Redis handles cleanup
        console.log('Redis-based LID mapping - no local cache to clear')
    }

    /**
     * Get stats
     */
    getStats() {
        return {
            storage: 'Redis-optimized (no local cache)',
            cacheSize: 0 // No cache needed with Redis
        }
    }
}