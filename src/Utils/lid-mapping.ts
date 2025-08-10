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
     * Store LID-PN mapping - USER PORTIONS ONLY
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
        
        // Extract USER portions only (no device IDs)
        const lidUser = lidDecoded.user
        const pnUser = pnDecoded.user
        
        // Redis-optimized: Direct storage, no redundant cache
        await this.keys.transaction(async () => {
            // Store bidirectional mapping - USER ONLY  
            await this.keys.set({
                'lid-mapping': {
                    [pnUser]: lidUser,              // "5511999999999" -> "55791994282113"
                    [`${lidUser}_1`]: pnUser        // "55791994282113_1" -> "5511999999999" (reverse lookup)
                }
            })
        })
        
        // Update sync cache after successful storage
        this.updateSyncCache(pnUser, lidUser)
        
        console.log(`✅ LID mapping stored: ${pnUser} ↔ ${lidUser}`)
    }

    /**
     * Get LID for PN - PRESERVES DEVICE ID
     * Redis-optimized: Direct lookup, no cache layer
     */
    async getLIDForPN(pn: string): Promise<string | null> {
        if (!isJidUser(pn)) return null
        
        const decoded = jidDecode(pn)
        if (!decoded) return null
        
        // Try direct lookup by user portion first
        const stored = await this.keys.get('lid-mapping', [decoded.user])
        let lidUser = stored[decoded.user]
        
        // CRITICAL FIX: If not found, try to see if this is actually a LID being passed as PN
        if (!lidUser && decoded.user.match(/^\d{12,15}$/)) {
            // This might be a base LID, check if we have the reverse mapping
            const reverseStored = await this.keys.get('lid-mapping', [`${decoded.user}_1`])
            const pnUser = reverseStored[`${decoded.user}_1`]
            if (pnUser) {
                // This is a LID that has a PN mapping, return it as-is since it's already a LID
                lidUser = decoded.user
            }
        }
        
        if (!lidUser || typeof lidUser !== 'string') return null
        
        // Update sync cache for immediate access
        this.updateSyncCache(decoded.user, lidUser)
        
        // CRITICAL: Preserve device ID from input
        return decoded.device !== undefined
            ? `${lidUser}:${decoded.device}@lid`
            : `${lidUser}@lid`
    }

    /**
     * Get PN for LID - PRESERVES DEVICE ID
     * Redis-optimized: Direct lookup, no cache layer
     */
    async getPNForLID(lid: string): Promise<string | null> {
        if (!isLidUser(lid)) return null
        
        const decoded = jidDecode(lid)
        if (!decoded) return null
        
        // Direct Redis lookup by user portion (with _1 suffix for reverse lookup)
        const stored = await this.keys.get('lid-mapping', [`${decoded.user}_1`])
        const pnUser = stored[`${decoded.user}_1`]
        
        if (!pnUser || typeof pnUser !== 'string') return null
        
        // Update sync cache for immediate access (reverse mapping)
        this.updateSyncCache(pnUser, decoded.user)
        
        // CRITICAL: Preserve device ID from input
        return decoded.device !== undefined
            ? `${pnUser}:${decoded.device}@s.whatsapp.net`
            : `${pnUser}@s.whatsapp.net`
    }

    /**
     * Check if a LID exists in our mappings (for validation)
     * This helps when we have a direct LID contact and need to verify it exists
     */
    async isLIDMapped(lid: string): Promise<boolean> {
        if (!isLidUser(lid)) return false
        
        const decoded = jidDecode(lid)
        if (!decoded) return false
        
        // Check both forward and reverse mappings
        const [forwardStored, reverseStored] = await Promise.all([
            this.keys.get('lid-mapping', [decoded.user]),
            this.keys.get('lid-mapping', [`${decoded.user}_1`])
        ])
        
        // LID is mapped if either direction exists
        return !!(forwardStored[decoded.user] || reverseStored[`${decoded.user}_1`])
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
     * Helper to manage small sync cache
     */
    private updateSyncCache(pnUser: string, lidUser: string): void {
        // Keep cache small - remove oldest if needed
        if (this.syncCache.size >= this.maxCacheSize) {
            const firstKey = this.syncCache.keys().next().value
            if (firstKey) {
                this.syncCache.delete(firstKey)
            }
        }
        this.syncCache.set(pnUser, lidUser)
    }

    /**
     * Fast synchronous cache lookup for retry scenarios
     */
    getFromCache(pn: string): string | null {
        if (!isJidUser(pn)) return null
        
        const decoded = jidDecode(pn)
        if (!decoded) return null
        
        // Check sync cache first
        const lidUser = this.syncCache.get(decoded.user)
        if (!lidUser) return null
        
        // CRITICAL: Preserve device ID from input
        return decoded.device !== undefined
            ? `${lidUser}:${decoded.device}@lid`
            : `${lidUser}@lid`
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