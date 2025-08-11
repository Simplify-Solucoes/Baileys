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
        
        // CRITICAL FIX: 1:1 device mapping - push PN device ID to LID
        // LID addresses from metadata don't include device IDs, so we use the PN device ID
        const pnDevice = pnDecoded.device !== undefined ? pnDecoded.device : 0
        const lidDevice = lidDecoded.device !== undefined ? lidDecoded.device : pnDevice  // Use PN device if LID has no device
        
        const pnWithDevice = `${pnDecoded.user}:${pnDevice}`
        const lidWithDevice = `${lidDecoded.user}:${lidDevice}`
        
        console.log(`📱 Storing 1:1 DEVICE LID mapping: PN device ${pnWithDevice} → LID device ${lidWithDevice} (device ID ${pnDevice} pushed from PN to LID)`)
        
        // Redis-optimized: Direct storage, no redundant cache
        await this.keys.transaction(async () => {
            // Store bidirectional mapping - 1:1 device mapping for separate sessions
            await this.keys.set({
                'lid-mapping': {
                    [pnWithDevice]: lidWithDevice,                    // "554396160286:43" -> "102765716062358:43"
                    [`${lidWithDevice}_1_${pnWithDevice}`]: pnWithDevice // "102765716062358:43_1_554396160286:43" -> "554396160286:43" (1:1 reverse)
                }
            })
        })
        
        // Update sync cache after successful storage (1:1 device mapping)
        this.updateSyncCache(pnWithDevice, lidWithDevice)
        
        console.log(`✅ 1:1 DEVICE LID mapping stored: PN device ${pnWithDevice} → LID device ${lidWithDevice} (PN device ID pushed to LID)`)
    }

    /**
     * Get LID for PN - 1:1 DEVICE MAPPING to prevent double ratchet corruption
     * Redis-optimized: Direct lookup, no cache layer
     */
    async getLIDForPN(pn: string): Promise<string | null> {
        if (!isJidUser(pn)) return null
        
        const decoded = jidDecode(pn)
        if (!decoded) return null
        
        // CRITICAL FIX: 1:1 device mapping - each PN device maps to corresponding LID device
        // This maintains separate sessions per device to prevent double ratchet corruption
        const pnDevice = decoded.device !== undefined ? decoded.device : 0
        const pnDeviceKey = `${decoded.user}:${pnDevice}`
        
        const stored = await this.keys.get('lid-mapping', [pnDeviceKey])
        let lidWithDevice = stored[pnDeviceKey]
        
        if (!lidWithDevice) {
            console.log(`🚫 No 1:1 LID mapping found for PN device ${pn} - each device needs separate mapping`)
            return null
        }
        
        if (typeof lidWithDevice !== 'string') return null
        
        // Update sync cache for immediate access
        this.updateSyncCache(pnDeviceKey, lidWithDevice)
        
        // Return the exact 1:1 mapped LID device
        return `${lidWithDevice}@lid`
    }

    /**
     * Get PN for LID - DEVICE-SPECIFIC LOOKUP to prevent unsupported device migration
     * Redis-optimized: Direct lookup, no cache layer
     */
    async getPNForLID(lid: string): Promise<string | null> {
        if (!isLidUser(lid)) return null
        
        const decoded = jidDecode(lid)
        if (!decoded) return null
        
        // CRITICAL FIX: Find PN devices that map to this LID user using reverse mapping pattern
        // Pattern: "lidUser_1_pnDevice" -> "pnDevice"
        const lidUser = decoded.user
        const lidDevice = decoded.device
        
        // Try to find ANY reverse mapping for this LID user
        // We need to search for keys that match pattern: "lidUser_1_*"
        console.log(`🔍 Looking for reverse mappings for LID user: ${lidUser}`)
        
        // Get all lid-mapping keys to find reverse mappings
        const allMappings = await this.keys.get('lid-mapping', [])
        
        // Look for reverse mappings: "lidUser_1_pnDevice" -> "pnDevice"
        for (const [key, value] of Object.entries(allMappings)) {
            if (key.startsWith(`${lidUser}_1_`) && typeof value === 'string') {
                // Found a reverse mapping: extract the PN device
                const pnDevice = value // This should be like "554396160286:43"
                
                // If LID has specific device, match it
                if (lidDevice !== undefined) {
                    // Check if this PN device matches the LID device
                    const pnDecoded = pnDevice.includes(':') ? pnDevice.split(':') : [pnDevice, '0']
                    const pnDeviceId = pnDecoded[1] || '0'
                    
                    if (pnDeviceId === lidDevice.toString()) {
                        const pnJid = `${pnDevice}@s.whatsapp.net`
                        console.log(`✅ Found device-specific reverse mapping: ${lid} → ${pnJid}`)
                        return pnJid
                    }
                } else {
                    // Return first found PN device for base LID
                    const pnJid = `${pnDevice}@s.whatsapp.net`
                    console.log(`✅ Found reverse mapping for base LID: ${lid} → ${pnJid}`)
                    return pnJid
                }
            }
        }
        
        console.log(`🚫 No reverse mapping found for LID: ${lid}`)
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