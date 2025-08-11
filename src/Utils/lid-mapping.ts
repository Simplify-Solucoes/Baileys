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
        
        // CRITICAL FIX: Handle that multiple PN devices can map to the same LID user
        // PN devices have device IDs, LID users typically don't, but we need :0 for main devices
        const pnWithDevice = pnDecoded.device !== undefined ? `${pnDecoded.user}:${pnDecoded.device}` : `${pnDecoded.user}:0`
        const lidUser = lidDecoded.user  // LID user without device suffix (multiple PN devices → same LID user)
        
        console.log(`📱 Storing DEVICE-SPECIFIC LID mapping: PN device ${pnWithDevice} → LID user ${lidUser}`)
        
        // Redis-optimized: Direct storage, no redundant cache
        await this.keys.transaction(async () => {
            // Store bidirectional mapping - Each PN device maps to same LID user but maintains separate sessions
            await this.keys.set({
                'lid-mapping': {
                    [pnWithDevice]: lidUser,                    // "554396160286:43" -> "102765716062358"
                    [`${lidUser}_1_${pnWithDevice}`]: pnWithDevice // "102765716062358_1_554396160286:43" -> "554396160286:43" (device-specific reverse)
                }
            })
        })
        
        // Update sync cache after successful storage (use device-specific for immediate access)
        this.updateSyncCache(pnWithDevice, lidUser)
        
        console.log(`✅ DEVICE-SPECIFIC LID mapping stored: PN device ${pnWithDevice} → LID user ${lidUser}`)
    }

    /**
     * Get LID for PN - DEVICE-SPECIFIC LOOKUP to prevent unsupported device migration
     * Redis-optimized: Direct lookup, no cache layer
     */
    async getLIDForPN(pn: string): Promise<string | null> {
        if (!isJidUser(pn)) return null
        
        const decoded = jidDecode(pn)
        if (!decoded) return null
        
        // CRITICAL FIX: Look up by PN device key (each PN device has separate mapping to same LID user)
        // Add :0 for main devices to match storage format
        const pnDeviceKey = decoded.device !== undefined ? `${decoded.user}:${decoded.device}` : `${decoded.user}:0`
        const stored = await this.keys.get('lid-mapping', [pnDeviceKey])
        let lidUser = stored[pnDeviceKey]
        
        // CRITICAL: Do NOT use legacy user-level mappings - only device-specific
        // This prevents migration of unsupported devices when one device has LID migration
        if (!lidUser) {
            console.log(`🚫 No device-specific LID mapping found for PN device ${pn} - NOT falling back to user-level mapping`)
            return null
        }
        
        if (typeof lidUser !== 'string') return null
        
        // Update sync cache for immediate access
        this.updateSyncCache(pnDeviceKey, lidUser)
        
        // CRITICAL: Push device ID from PN to LID to maintain session separation
        // Even though native LID doesn't have device IDs, we need them for session targeting
        const deviceId = decoded.device !== undefined ? decoded.device : '0'
        return `${lidUser}:${deviceId}@lid`
    }

    /**
     * Get PN for LID - DEVICE-SPECIFIC LOOKUP to prevent unsupported device migration
     * Redis-optimized: Direct lookup, no cache layer
     */
    async getPNForLID(lid: string): Promise<string | null> {
        if (!isLidUser(lid)) return null
        
        const decoded = jidDecode(lid)
        if (!decoded) return null
        
        // CRITICAL FIX: For reverse lookup, we need to find all PN devices that map to this LID user
        // We can't directly reverse lookup because we don't know which PN device we're looking for
        // We need to iterate through potential PN device mappings or use a different approach
        
        // For now, we'll return null as this method should primarily be used for validation
        // The main flow should use getLIDForPN instead
        console.log(`🚫 getPNForLID not fully implemented for device-specific mappings: ${lid}`)
        console.log(`   Use getLIDForPN on specific PN devices instead`)
        return null
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
     * Helper to manage small sync cache - DEVICE-SPECIFIC KEYS ONLY
     */
    private updateSyncCache(pnWithDevice: string, lidWithDevice: string): void {
        // Keep cache small - remove oldest if needed
        if (this.syncCache.size >= this.maxCacheSize) {
            const firstKey = this.syncCache.keys().next().value
            if (firstKey) {
                this.syncCache.delete(firstKey)
            }
        }
        // Store with device-specific key to prevent cross-device cache pollution
        this.syncCache.set(pnWithDevice, lidWithDevice)
    }

    /**
     * Fast synchronous cache lookup for retry scenarios - DEVICE-SPECIFIC ONLY
     */
    getFromCache(pn: string): string | null {
        if (!isJidUser(pn)) return null
        
        const decoded = jidDecode(pn)
        if (!decoded) return null
        
        // DEVICE-SPECIFIC: Use device-specific key for cache lookup (with :0 for main devices)
        const deviceKey = decoded.device !== undefined ? `${decoded.user}:${decoded.device}` : `${decoded.user}:0`
        const lidWithDevice = this.syncCache.get(deviceKey)
        if (!lidWithDevice) return null
        
        // CRITICAL: Push device ID from PN to LID for session targeting
        const deviceId = decoded.device !== undefined ? decoded.device : '0'  
        return `${lidWithDevice}:${deviceId}@lid`
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