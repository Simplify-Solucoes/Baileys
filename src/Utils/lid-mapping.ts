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
        
        // CRITICAL CHANGE: Store DEVICE-SPECIFIC mappings to prevent migration of unsupported devices
        // Extract full JID (with device info) for device-specific mapping
        const lidWithDevice = lidDecoded.device !== undefined ? `${lidDecoded.user}:${lidDecoded.device}` : lidDecoded.user
        const pnWithDevice = pnDecoded.device !== undefined ? `${pnDecoded.user}:${pnDecoded.device}` : pnDecoded.user
        
        console.log(`📱 Storing DEVICE-SPECIFIC LID mapping: ${pnWithDevice} ↔ ${lidWithDevice}`)
        
        // Redis-optimized: Direct storage, no redundant cache
        await this.keys.transaction(async () => {
            // Store bidirectional mapping - DEVICE-SPECIFIC to prevent cross-device migration  
            await this.keys.set({
                'lid-mapping': {
                    [pnWithDevice]: lidWithDevice,              // "5511999999999:43" -> "55791994282113:43"
                    [`${lidWithDevice}_1`]: pnWithDevice        // "55791994282113:43_1" -> "5511999999999:43" (reverse lookup)
                }
            })
        })
        
        // Update sync cache after successful storage (use device-specific for immediate access)
        this.updateSyncCache(pnWithDevice, lidWithDevice)
        
        console.log(`✅ DEVICE-SPECIFIC LID mapping stored: ${pnWithDevice} ↔ ${lidWithDevice}`)
    }

    /**
     * Get LID for PN - DEVICE-SPECIFIC LOOKUP to prevent unsupported device migration
     * Redis-optimized: Direct lookup, no cache layer
     */
    async getLIDForPN(pn: string): Promise<string | null> {
        if (!isJidUser(pn)) return null
        
        const decoded = jidDecode(pn)
        if (!decoded) return null
        
        // CRITICAL CHANGE: Look up by DEVICE-SPECIFIC key first (exact device match)
        const deviceKey = decoded.device !== undefined ? `${decoded.user}:${decoded.device}` : decoded.user
        const stored = await this.keys.get('lid-mapping', [deviceKey])
        let lidWithDevice = stored[deviceKey]
        
        // If device-specific mapping not found, try base user lookup (legacy compatibility)
        if (!lidWithDevice) {
            const legacyStored = await this.keys.get('lid-mapping', [decoded.user])
            const legacyLidUser = legacyStored[decoded.user]
            if (legacyLidUser) {
                console.log(`⚠️ Using legacy user-level LID mapping for ${pn} → ${legacyLidUser} (consider device-specific migration)`)
                lidWithDevice = legacyLidUser
            }
        }
        
        // CRITICAL FIX: If not found, try to see if this is actually a LID being passed as PN
        if (!lidWithDevice && decoded.user.match(/^\d{12,15}$/)) {
            // This might be a base LID, check if we have the reverse mapping
            const reverseKey = decoded.device !== undefined ? `${decoded.user}:${decoded.device}_1` : `${decoded.user}_1`
            const reverseStored = await this.keys.get('lid-mapping', [reverseKey])
            const pnWithDevice = reverseStored[reverseKey]
            if (pnWithDevice) {
                // This is a LID that has a PN mapping, return it as-is since it's already a LID
                lidWithDevice = deviceKey
            }
        }
        
        if (!lidWithDevice || typeof lidWithDevice !== 'string') return null
        
        // Update sync cache for immediate access
        this.updateSyncCache(deviceKey, lidWithDevice)
        
        // Parse the lidWithDevice to get user and device parts
        const [lidUser, lidDeviceStr] = lidWithDevice.includes(':') ? lidWithDevice.split(':') : [lidWithDevice, undefined]
        
        // CRITICAL: Return properly formatted LID JID
        return lidDeviceStr !== undefined
            ? `${lidUser}:${lidDeviceStr}@lid`
            : `${lidUser}@lid`
    }

    /**
     * Get PN for LID - DEVICE-SPECIFIC LOOKUP to prevent unsupported device migration
     * Redis-optimized: Direct lookup, no cache layer
     */
    async getPNForLID(lid: string): Promise<string | null> {
        if (!isLidUser(lid)) return null
        
        const decoded = jidDecode(lid)
        if (!decoded) return null
        
        // CRITICAL CHANGE: Look up by DEVICE-SPECIFIC key first (with _1 suffix for reverse lookup)
        const deviceKey = decoded.device !== undefined ? `${decoded.user}:${decoded.device}` : decoded.user
        const reverseKey = `${deviceKey}_1`
        const stored = await this.keys.get('lid-mapping', [reverseKey])
        let pnWithDevice = stored[reverseKey]
        
        // If device-specific mapping not found, try base user lookup (legacy compatibility)
        if (!pnWithDevice) {
            const legacyStored = await this.keys.get('lid-mapping', [`${decoded.user}_1`])
            const legacyPnUser = legacyStored[`${decoded.user}_1`]
            if (legacyPnUser) {
                console.log(`⚠️ Using legacy user-level PN mapping for ${lid} → ${legacyPnUser} (consider device-specific migration)`)
                pnWithDevice = legacyPnUser
            }
        }
        
        if (!pnWithDevice || typeof pnWithDevice !== 'string') return null
        
        // Update sync cache for immediate access (reverse mapping)
        this.updateSyncCache(pnWithDevice, deviceKey)
        
        // Parse the pnWithDevice to get user and device parts
        const [pnUser, pnDeviceStr] = pnWithDevice.includes(':') ? pnWithDevice.split(':') : [pnWithDevice, undefined]
        
        // CRITICAL: Return properly formatted PN JID
        return pnDeviceStr !== undefined
            ? `${pnUser}:${pnDeviceStr}@s.whatsapp.net`
            : `${pnUser}@s.whatsapp.net`
    }

    /**
     * Check if a LID exists in our mappings (for validation) - DEVICE-SPECIFIC
     * This helps when we have a direct LID contact and need to verify it exists
     */
    async isLIDMapped(lid: string): Promise<boolean> {
        if (!isLidUser(lid)) return false
        
        const decoded = jidDecode(lid)
        if (!decoded) return false
        
        // DEVICE-SPECIFIC: Check both forward and reverse mappings
        const deviceKey = decoded.device !== undefined ? `${decoded.user}:${decoded.device}` : decoded.user
        const reverseKey = `${deviceKey}_1`
        
        const [deviceStored, reverseStored, legacyForward, legacyReverse] = await Promise.all([
            this.keys.get('lid-mapping', [deviceKey]),
            this.keys.get('lid-mapping', [reverseKey]),
            // Legacy compatibility checks
            this.keys.get('lid-mapping', [decoded.user]),
            this.keys.get('lid-mapping', [`${decoded.user}_1`])
        ])
        
        // LID is mapped if either device-specific or legacy mapping exists
        return !!(
            deviceStored[deviceKey] || 
            reverseStored[reverseKey] ||
            legacyForward[decoded.user] || 
            legacyReverse[`${decoded.user}_1`]
        )
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