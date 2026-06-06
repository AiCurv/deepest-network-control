package com.dnc.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.dnc.dns.DnsConfig
import com.dnc.dns.BlockResponseType
import com.dnc.ui.theme.*

@Composable
fun SettingsScreen(
    onInstallCaCert: () -> Unit = {},
    isCaInstalled: Boolean = false,
    httpsFilteringEnabled: Boolean = false,
    onHttpsFilteringChanged: (Boolean) -> Unit = {},
    excludedDomains: List<String> = listOf("chase.com", "paypal.com", "bankofamerica.com"),
    onAddExcludedDomain: (String) -> Unit = {},
    onRemoveExcludedDomain: (String) -> Unit = {}
) {
    var selectedDns by remember { mutableStateOf(0) }
    var httpsFiltering by remember { mutableStateOf(httpsFilteringEnabled) }
    var redirectBlockAction by remember { mutableStateOf(0) }
    var autoStart by remember { mutableStateOf(false) }
    var newExcludedDomain by remember { mutableStateOf("") }
    val initialExcludedDomains = excludedDomains
    var excludedDomains by remember { mutableStateOf(initialExcludedDomains) }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // DNS Settings
        item {
            SectionHeader("DNS SETTINGS")
        }

        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = DncSurfaceVariant)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("Upstream DNS Provider", fontWeight = FontWeight.SemiBold, color = DncOnSurface)
                    Spacer(modifier = Modifier.height(8.dp))

                    val dnsProviders = DnsConfig.ALL_PROVIDERS.map { it.name } + "Custom"
                    dnsProviders.forEachIndexed { index, name ->
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.padding(vertical = 4.dp)
                        ) {
                            RadioButton(
                                selected = selectedDns == index,
                                onClick = { selectedDns = index },
                                colors = RadioButtonDefaults.colors(selectedColor = DncCyan)
                            )
                            Text(name, color = DncOnSurface, style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                }
            }
        }

        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = DncSurfaceVariant)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("Block Response Type", fontWeight = FontWeight.SemiBold, color = DncOnSurface)
                    Spacer(modifier = Modifier.height(8.dp))

                    val blockTypes = listOf("0.0.0.0 (Empty)", "NXDOMAIN (Not Found)", "REFUSED")
                    blockTypes.forEachIndexed { index, name ->
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.padding(vertical = 4.dp)
                        ) {
                            RadioButton(
                                selected = redirectBlockAction == index,
                                onClick = { redirectBlockAction = index },
                                colors = RadioButtonDefaults.colors(selectedColor = DncCyan)
                            )
                            Text(name, color = DncOnSurface, style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                }
            }
        }

        // HTTPS Filtering
        item {
            SectionHeader("HTTPS FILTERING")
        }

        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = DncSurfaceVariant)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("HTTPS Inspection", fontWeight = FontWeight.SemiBold, color = DncOnSurface)
                            Text(
                                "Decrypt and inspect HTTPS traffic",
                                style = MaterialTheme.typography.bodySmall,
                                color = DncOnSurfaceVariant
                            )
                        }
                        Switch(
                            checked = httpsFiltering,
                            onCheckedChange = {
                                httpsFiltering = it
                                onHttpsFilteringChanged(it)
                            },
                            colors = SwitchDefaults.colors(
                                checkedTrackColor = DncCyan,
                                checkedThumbColor = Color.Black
                            )
                        )
                    }

                    if (httpsFiltering) {
                        Spacer(modifier = Modifier.height(12.dp))

                        // CA Cert Status
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                imageVector = if (isCaInstalled) Icons.Filled.CheckCircle else Icons.Filled.Warning,
                                contentDescription = null,
                                tint = if (isCaInstalled) DncGreen else DncOrange,
                                modifier = Modifier.size(20.dp)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = if (isCaInstalled) "CA Certificate installed" else "CA Certificate not installed",
                                style = MaterialTheme.typography.bodySmall,
                                color = if (isCaInstalled) DncGreen else DncOrange
                            )
                        }

                        if (!isCaInstalled) {
                            Spacer(modifier = Modifier.height(8.dp))
                            Button(
                                onClick = onInstallCaCert,
                                shape = RoundedCornerShape(12.dp),
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = DncCyan,
                                    contentColor = Color.Black
                                )
                            ) {
                                Icon(Icons.Filled.VerifiedUser, null, modifier = Modifier.size(18.dp))
                                Spacer(modifier = Modifier.width(8.dp))
                                Text("Install CA Certificate")
                            }
                        }
                    }
                }
            }
        }

        // Excluded Domains
        item {
            SectionHeader("EXCLUDED DOMAINS (HTTPS)")
        }

        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = DncSurfaceVariant)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        "These domains will NOT be inspected (e.g., banking)",
                        style = MaterialTheme.typography.bodySmall,
                        color = DncOnSurfaceVariant
                    )
                    Spacer(modifier = Modifier.height(8.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        OutlinedTextField(
                            value = newExcludedDomain,
                            onValueChange = { newExcludedDomain = it },
                            placeholder = { Text("domain.com") },
                            modifier = Modifier.weight(1f),
                            singleLine = true,
                            shape = RoundedCornerShape(12.dp),
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedBorderColor = DncCyan,
                                unfocusedBorderColor = DncOnSurfaceVariant,
                                cursorColor = DncCyan,
                                focusedTextColor = DncOnSurface,
                                unfocusedTextColor = DncOnSurface
                            )
                        )
                        IconButton(onClick = {
                            if (newExcludedDomain.isNotBlank()) {
                                excludedDomains = excludedDomains + newExcludedDomain
                                onAddExcludedDomain(newExcludedDomain)
                                newExcludedDomain = ""
                            }
                        }) {
                            Icon(Icons.Filled.Add, "Add", tint = DncCyan)
                        }
                    }

                    excludedDomains.forEach { domain ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 2.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = domain,
                                modifier = Modifier.weight(1f),
                                style = MaterialTheme.typography.bodySmall,
                                color = DncOnSurface
                            )
                            IconButton(
                                onClick = {
                                    excludedDomains = excludedDomains - domain
                                    onRemoveExcludedDomain(domain)
                                },
                                modifier = Modifier.size(24.dp)
                            ) {
                                Icon(Icons.Filled.Close, "Remove", tint = DncRed, modifier = Modifier.size(16.dp))
                            }
                        }
                    }
                }
            }
        }

        // Advanced
        item {
            SectionHeader("ADVANCED")
        }

        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = DncSurfaceVariant)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("Auto-start on boot", fontWeight = FontWeight.SemiBold, color = DncOnSurface)
                            Text(
                                "Start DNC VPN when device boots",
                                style = MaterialTheme.typography.bodySmall,
                                color = DncOnSurfaceVariant
                            )
                        }
                        Switch(
                            checked = autoStart,
                            onCheckedChange = { autoStart = it },
                            colors = SwitchDefaults.colors(
                                checkedTrackColor = DncCyan,
                                checkedThumbColor = Color.Black
                            )
                        )
                    }
                }
            }
        }

        // About
        item {
            SectionHeader("ABOUT")
        }

        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = DncSurfaceVariant)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("Deepest Network Control", fontWeight = FontWeight.Bold, color = DncOnSurface)
                    Text("Version 1.0.0-alpha", style = MaterialTheme.typography.bodySmall, color = DncOnSurfaceVariant)
                    Spacer(modifier = Modifier.height(4.dp))
                    Text("License: GPL-3.0", style = MaterialTheme.typography.bodySmall, color = DncOnSurfaceVariant)
                    Text("github.com/dnc-project/deepest-network-control", style = MaterialTheme.typography.bodySmall, color = DncCyan)
                }
            }
        }

        item {
            Spacer(modifier = Modifier.height(32.dp))
        }
    }
}

@Composable
private fun SectionHeader(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.labelMedium,
        fontWeight = FontWeight.Bold,
        color = DncOnSurfaceVariant,
        modifier = Modifier.padding(top = 8.dp)
    )
}
