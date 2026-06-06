package com.dnc.ui.screens

import androidx.compose.foundation.background
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.dnc.proxy.HttpProxy
import com.dnc.ui.theme.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LogScreen(
    logEntries: List<HttpProxy.RequestLogEntry>
) {
    var filterMode by remember { mutableStateOf(LogFilter.ALL) }
    var searchText by remember { mutableStateOf("") }

    val filteredEntries = logEntries.filter { entry ->
        val matchesFilter = when (filterMode) {
            LogFilter.ALL -> true
            LogFilter.BLOCKED -> entry.action == HttpProxy.Action.BLOCKED || entry.action == HttpProxy.Action.REDIRECT_BLOCKED
            LogFilter.ALLOWED -> entry.action == HttpProxy.Action.ALLOWED
        }
        val matchesSearch = searchText.isBlank() || entry.url.contains(searchText, ignoreCase = true)
        matchesFilter && matchesSearch
    }

    Column(
        modifier = Modifier.fillMaxSize()
    ) {
        // Filter bar
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            FilterChip(
                selected = filterMode == LogFilter.ALL,
                onClick = { filterMode = LogFilter.ALL },
                label = { Text("All") },
                colors = FilterChipDefaults.filterChipColors(
                    selectedContainerColor = DncCyan.copy(alpha = 0.2f),
                    selectedLabelColor = DncCyan
                )
            )
            FilterChip(
                selected = filterMode == LogFilter.BLOCKED,
                onClick = { filterMode = LogFilter.BLOCKED },
                label = { Text("Blocked") },
                colors = FilterChipDefaults.filterChipColors(
                    selectedContainerColor = DncRed.copy(alpha = 0.2f),
                    selectedLabelColor = DncRed
                )
            )
            FilterChip(
                selected = filterMode == LogFilter.ALLOWED,
                onClick = { filterMode = LogFilter.ALLOWED },
                label = { Text("Allowed") },
                colors = FilterChipDefaults.filterChipColors(
                    selectedContainerColor = DncGreen.copy(alpha = 0.2f),
                    selectedLabelColor = DncGreen
                )
            )
        }

        // Search bar
        OutlinedTextField(
            value = searchText,
            onValueChange = { searchText = it },
            placeholder = { Text("Search domain...") },
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp),
            singleLine = true,
            shape = RoundedCornerShape(12.dp),
            leadingIcon = {
                Icon(Icons.Filled.Search, null, tint = DncOnSurfaceVariant)
            },
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = DncCyan,
                unfocusedBorderColor = DncOnSurfaceVariant,
                cursorColor = DncCyan,
                focusedTextColor = DncOnSurface,
                unfocusedTextColor = DncOnSurface
            )
        )

        Spacer(modifier = Modifier.height(8.dp))

        // Log entries
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            if (filteredEntries.isEmpty()) {
                item {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(32.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = "No requests logged yet.\nStart the VPN to see network activity.",
                            color = DncOnSurfaceVariant,
                            style = MaterialTheme.typography.bodyMedium
                        )
                    }
                }
            }

            items(filteredEntries) { entry ->
                LogEntryItem(entry)
            }
        }
    }
}

@Composable
private fun LogEntryItem(entry: HttpProxy.RequestLogEntry) {
    val (actionColor, actionText) = entry.action.toLogDisplay()

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(8.dp),
        colors = CardDefaults.cardColors(containerColor = DncSurfaceVariant.copy(alpha = 0.5f))
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(10.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Action indicator
            Box(
                modifier = Modifier
                    .size(8.dp)
                    .background(actionColor, RoundedCornerShape(4.dp))
            )

            Spacer(modifier = Modifier.width(10.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = entry.url,
                    style = MaterialTheme.typography.bodySmall,
                    color = DncOnSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    fontFamily = FontFamily.Monospace
                )
                Row {
                    Text(
                        text = "${entry.method}",
                        style = MaterialTheme.typography.labelSmall,
                        color = DncOnSurfaceVariant
                    )
                    if (entry.statusCode != null) {
                        Text(
                            text = " · ${entry.statusCode}",
                            style = MaterialTheme.typography.labelSmall,
                            color = DncOnSurfaceVariant
                        )
                    }
                    if (entry.matchedRule != null) {
                        Text(
                            text = " · ${entry.matchedRule}",
                            style = MaterialTheme.typography.labelSmall,
                            color = DncOnSurfaceVariant,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                }
            }

            Text(
                text = actionText,
                style = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.Bold,
                color = actionColor,
                fontSize = 9.sp
            )
        }
    }
}

enum class LogFilter {
    ALL, BLOCKED, ALLOWED
}

// Extension: map new Phase 4 Action types for log display
fun HttpProxy.Action.toLogDisplay(): Pair<Color, String> {
    return when (this) {
        HttpProxy.Action.BLOCKED -> DncRed to "BLOCKED"
        HttpProxy.Action.REDIRECT_BLOCKED -> DncOrange to "REDIRECT BLOCKED"
        HttpProxy.Action.ALLOWED -> DncGreen to "ALLOWED"
        HttpProxy.Action.REDIRECTED -> DncPurple to "REDIRECTED"
        HttpProxy.Action.PARAM_REMOVED -> DncCyan to "PARAM REMOVED"
        HttpProxy.Action.CSP_INJECTED -> Color(0xFFFFD600) to "CSP INJECTED"
        HttpProxy.Action.HTML_MODIFIED -> Color(0xFFE040FB) to "HTML MODIFIED"
    }
}
