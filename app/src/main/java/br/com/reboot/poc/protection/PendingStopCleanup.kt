package br.com.reboot.poc.protection

import java.util.UUID

data class PendingStopCleanup(
    val sessionKey: String
) {
    init {
        require(
            runCatching {
                UUID.fromString(sessionKey).toString() ==
                        sessionKey
            }.getOrDefault(false)
        ) {
            "Invalid session key"
        }
    }
}
