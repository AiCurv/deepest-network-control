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
import com.dnc.filter.FilterEngine
import com.dnc.ui.theme.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun FilterListsScreen(
    filterEngine: FilterEngine
) {
    var filterLists by remember { mutableStateOf(filterEngine.getFilterLists()) }
    var customRules by remember { mutableStateOf(filterEngine.getCustomRules()) }
    var newRuleText by remember { mutableStateOf("") }
    var newListUrl by remember { mutableStateOf("") }
    var isLoading by remember { mutableStateOf(false) }
    var statusMessage by remember { mutableStateOf("") }

    // Use rememberCoroutineScope for safe coroutine management
    val coroutineScope = rememberCoroutineScope()

    // Refresh list data periodically
    LaunchedEffect(Unit) {
        while (true) {
            try {
                filterLists = filterEngine.getFilterLists()
                customRules = filterEngine.getCustomRules()
            } catch (_: Exception) {}
            kotlinx.coroutines.delay(3000)
        }
    }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // Header
        item {
            Text(
                text = "FILTER LISTS",
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
                color = DncCyan
            )
            Text(
                text = "Subscribe to filter lists for ad and tracker blocking",
                style = MaterialTheme.typography.bodySmall,
                color = DncOnSurfaceVariant
            )
        }

        // Status message
        if (statusMessage.isNotBlank()) {
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp),
                    colors = CardDefaults.cardColors(containerColor = DncSurfaceVariant)
                ) {
                    Row(
                        modifier = Modifier.padding(12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        if (isLoading) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(20.dp),
                                strokeWidth = 2.dp,
                                color = DncCyan
                            )
                            Spacer(modifier = Modifier.width(12.dp))
                        }
                        Text(
                            text = statusMessage,
                            style = MaterialTheme.typography.bodySmall,
                            color = DncOnSurface
                        )
                    }
                }
            }
        }

        // Filter Lists
        items(filterLists) { listInfo ->
            var enabled by remember(listInfo.id) { mutableStateOf(listInfo.enabled) }
            var ruleCount by remember(listInfo.id) { mutableIntStateOf(listInfo.ruleCount) }

            // Sync from engine when lists update
            LaunchedEffect(filterLists) {
                val current = filterEngine.getFilterLists().find { it.id == listInfo.id }
                if (current != null) {
                    enabled = current.enabled
                    ruleCount = current.ruleCount
                }
            }

            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(
                    containerColor = DncSurfaceVariant
                )
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = listInfo.name,
                            fontWeight = FontWeight.SemiBold,
                            color = DncOnSurface
                        )
                        Text(
                            text = "${ruleCount} rules" +
                                    if (listInfo.lastUpdated > 0) " · Updated ${formatTimestamp(listInfo.lastUpdated)}" else "",
                            style = MaterialTheme.typography.bodySmall,
                            color = if (ruleCount > 0) DncGreen else DncOnSurfaceVariant,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                    Switch(
                        checked = enabled,
                        onCheckedChange = { newEnabled ->
                            enabled = newEnabled
                            if (newEnabled) {
                                // Download and activate the filter list
                                isLoading = true
                                statusMessage = "Downloading ${listInfo.name}..."
                                coroutineScope.launch(Dispatchers.IO) {
                                    try {
                                        val result = filterEngine.addFilterList(listInfo.id, listInfo.name, listInfo.url)
                                        withContext(Dispatchers.Main) {
                                            result.onSuccess { count ->
                                                ruleCount = count
                                                statusMessage = "Loaded $count rules from ${listInfo.name}"
                                            }.onFailure { error ->
                                                statusMessage = "Failed: ${error.message}"
                                                enabled = false // Revert on failure
                                            }
                                            isLoading = false
                                            filterLists = filterEngine.getFilterLists()
                                        }
                                    } catch (e: Exception) {
                                        withContext(Dispatchers.Main) {
                                            statusMessage = "Error: ${e.message}"
                                            enabled = false
                                            isLoading = false
                                        }
                                    }
                                }
                            } else {
                                // Remove the filter list rules
                                try {
                                    filterEngine.removeFilterList(listInfo.id)
                                    ruleCount = 0
                                    filterLists = filterEngine.getFilterLists()
                                    statusMessage = "Removed ${listInfo.name}"
                                } catch (e: Exception) {
                                    statusMessage = "Error removing: ${e.message}"
                                }
                            }
                        },
                        colors = SwitchDefaults.colors(
                            checkedTrackColor = DncCyan,
                            checkedThumbColor = Color.Black
                        )
                    )
                }
            }
        }

        // Add Custom List
        item {
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = "ADD CUSTOM LIST",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                color = DncPurple
            )
            Spacer(modifier = Modifier.height(8.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                OutlinedTextField(
                    value = newListUrl,
                    onValueChange = { newListUrl = it },
                    placeholder = { Text("https://example.com/filter.txt") },
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
                IconButton(
                    onClick = {
                        if (newListUrl.isNotBlank()) {
                            val url = newListUrl.trim()
                            newListUrl = ""
                            isLoading = true
                            statusMessage = "Downloading custom list..."
                            coroutineScope.launch(Dispatchers.IO) {
                                try {
                                    val id = "custom-${System.currentTimeMillis()}"
                                    val name = url.substringAfterLast("/").substringBefore(".")
                                        .ifBlank { "Custom List" }
                                    val result = filterEngine.addFilterList(id, name, url)
                                    withContext(Dispatchers.Main) {
                                        result.onSuccess { count ->
                                            statusMessage = "Loaded $count rules from custom list"
                                        }.onFailure { error ->
                                            statusMessage = "Failed: ${error.message}"
                                        }
                                        isLoading = false
                                        filterLists = filterEngine.getFilterLists()
                                    }
                                } catch (e: Exception) {
                                    withContext(Dispatchers.Main) {
                                        statusMessage = "Error: ${e.message}"
                                        isLoading = false
                                    }
                                }
                            }
                        }
                    }
                ) {
                    Icon(Icons.Filled.Add, "Add", tint = DncCyan)
                }
            }
        }

        // My Rules Section
        item {
            Spacer(modifier = Modifier.height(16.dp))
            Text(
                text = "MY RULES",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                color = DncPurple
            )
            Text(
                text = "||ads.example.com^  or  @@||allowed.com^",
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
                    value = newRuleText,
                    onValueChange = { newRuleText = it },
                    placeholder = { Text("||tracker.com^") },
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
                IconButton(
                    onClick = {
                        if (newRuleText.isNotBlank()) {
                            try {
                                val rule = filterEngine.addCustomRule(newRuleText)
                                if (rule != null) {
                                    statusMessage = "Rule added: ${newRuleText.trim()}"
                                } else {
                                    statusMessage = "Invalid rule syntax — check format"
                                }
                                newRuleText = ""
                                customRules = filterEngine.getCustomRules()
                            } catch (e: Exception) {
                                statusMessage = "Error adding rule: ${e.message}"
                                newRuleText = ""
                            }
                        }
                    }
                ) {
                    Icon(Icons.Filled.Add, "Add Rule", tint = DncCyan)
                }
            }
        }

        // Custom Rules List
        items(customRules) { rule ->
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp),
                colors = CardDefaults.cardColors(containerColor = DncSurface.copy(alpha = 0.5f))
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = rule.rawText,
                        modifier = Modifier.weight(1f),
                        style = MaterialTheme.typography.bodySmall,
                        color = DncOnSurface,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis
                    )
                    IconButton(
                        onClick = {
                            try {
                                filterEngine.removeCustomRule(rule.rawText)
                                customRules = filterEngine.getCustomRules()
                            } catch (_: Exception) {}
                        }
                    ) {
                        Icon(Icons.Filled.Delete, "Delete", tint = DncRed, modifier = Modifier.size(20.dp))
                    }
                }
            }
        }
    }
}

private fun formatTimestamp(timestamp: Long): String {
    val diff = System.currentTimeMillis() - timestamp
    return when {
        diff < 60_000 -> "just now"
        diff < 3_600_000 -> "${diff / 60_000}m ago"
        diff < 86_400_000 -> "${diff / 3_600_000}h ago"
        else -> "${diff / 86_400_000}d ago"
    }
}
