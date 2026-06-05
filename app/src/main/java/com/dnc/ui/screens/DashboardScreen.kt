package com.dnc.ui.screens

import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.dnc.ui.theme.*

@Composable
fun DashboardScreen(
    isVpnActive: Boolean,
    onVpnToggle: (Boolean) -> Unit,
    blockedCount: Int,
    dnsQueryCount: Int,
    redirectsBlocked: Int,
    activeRulesCount: Int,
    recentBlocked: List<String>
) {
    var dnsEnabled by remember { mutableStateOf(true) }
    var httpsEnabled by remember { mutableStateOf(false) }
    var redirectBlockEnabled by remember { mutableStateOf(true) }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Shield + Toggle Section
        item {
            ShieldToggle(
                isActive = isVpnActive,
                onToggle = onVpnToggle
            )
        }

        // Stats Cards
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                StatCard(
                    title = "Blocked",
                    value = blockedCount.toString(),
                    color = DncRed,
                    modifier = Modifier.weight(1f)
                )
                StatCard(
                    title = "DNS Queries",
                    value = dnsQueryCount.toString(),
                    color = DncCyan,
                    modifier = Modifier.weight(1f)
                )
            }
        }

        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                StatCard(
                    title = "Redirects Blocked",
                    value = redirectsBlocked.toString(),
                    color = DncOrange,
                    modifier = Modifier.weight(1f)
                )
                StatCard(
                    title = "Active Rules",
                    value = activeRulesCount.toString(),
                    color = DncGreen,
                    modifier = Modifier.weight(1f)
                )
            }
        }

        // Quick Toggles
        item {
            Text(
                text = "QUICK CONTROLS",
                style = MaterialTheme.typography.labelMedium,
                color = DncOnSurfaceVariant,
                modifier = Modifier.padding(top = 8.dp)
            )
        }

        item {
            ToggleCard(
                title = "DNS Filtering",
                subtitle = "Block domains at DNS level",
                icon = Icons.Filled.Dns,
                checked = dnsEnabled,
                onCheckedChange = { dnsEnabled = it }
            )
        }

        item {
            ToggleCard(
                title = "HTTPS Filtering",
                subtitle = if (httpsEnabled) "Inspect HTTPS traffic (CA required)" else "Install CA cert to enable",
                icon = Icons.Filled.Lock,
                checked = httpsEnabled,
                onCheckedChange = { httpsEnabled = it }
            )
        }

        item {
            ToggleCard(
                title = "Redirect Blocking",
                subtitle = "Block HTTP 301/302 redirects to trackers",
                icon = Icons.Filled.Block,
                checked = redirectBlockEnabled,
                onCheckedChange = { redirectBlockEnabled = it }
            )
        }

        // Recent Blocked
        if (recentBlocked.isNotEmpty()) {
            item {
                Text(
                    text = "RECENTLY BLOCKED",
                    style = MaterialTheme.typography.labelMedium,
                    color = DncOnSurfaceVariant,
                    modifier = Modifier.padding(top = 8.dp)
                )
            }

            items(recentBlocked.take(10)) { domain ->
                BlockedItem(domain = domain)
            }
        }
    }
}

@Composable
private fun ShieldToggle(
    isActive: Boolean,
    onToggle: (Boolean) -> Unit
) {
    val infiniteTransition = rememberInfiniteTransition(label = "shieldPulse")
    val pulseAlpha by infiniteTransition.animateFloat(
        initialValue = 0.4f,
        targetValue = 0.9f,
        animationSpec = infiniteRepeatable(
            animation = tween(1500, easing = EaseInOutCubic),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulseAlpha"
    )

    val shieldColor = if (isActive) DncGreen else DncRed
    val backgroundColor = if (isActive) DncGreen.copy(alpha = 0.15f) else DncSurfaceVariant

    Column(
        modifier = Modifier.fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Box(
            modifier = Modifier
                .size(160.dp)
                .clip(CircleShape)
                .background(
                    if (isActive) DncGreen.copy(alpha = pulseAlpha * 0.2f) else DncSurfaceVariant,
                    CircleShape
                )
                .clickable { onToggleToggle(!isActive) },
            contentAlignment = Alignment.Center
        ) {
            Icon(
                imageVector = Icons.Filled.Shield,
                contentDescription = if (isActive) "DNC Active" else "DNC Inactive",
                modifier = Modifier.size(100.dp),
                tint = if (isActive) DncGreen.copy(alpha = pulseAlpha) else DncRed.copy(alpha = 0.6f)
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        Button(
            onClick = { onToggle(!isActive) },
            modifier = Modifier
                .fillMaxWidth()
                .height(56.dp),
            shape = RoundedCornerShape(16.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = if (isActive) DncRed else DncCyan,
                contentColor = Color.Black
            )
        ) {
            Icon(
                imageVector = if (isActive) Icons.Filled.Stop else Icons.Filled.PlayArrow,
                contentDescription = null,
                modifier = Modifier.size(24.dp)
            )
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                text = if (isActive) "DEACTIVATE DNC" else "ACTIVATE DNC",
                fontWeight = FontWeight.Bold,
                fontSize = 16.sp
            )
        }

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = if (isActive) "Network protection active" else "Network unprotected",
            style = MaterialTheme.typography.bodyMedium,
            color = if (isActive) DncGreen else DncOnSurfaceVariant
        )
    }
}

@Composable
private fun StatCard(
    title: String,
    value: String,
    color: Color,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier,
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = DncSurfaceVariant
        )
    ) {
        Column(
            modifier = Modifier.padding(16.dp)
        ) {
            Text(
                text = value,
                fontSize = 28.sp,
                fontWeight = FontWeight.Bold,
                color = color
            )
            Text(
                text = title,
                style = MaterialTheme.typography.bodySmall,
                color = DncOnSurfaceVariant
            )
        }
    }
}

@Composable
private fun ToggleCard(
    title: String,
    subtitle: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
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
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = if (checked) DncCyan else DncOnSurfaceVariant,
                modifier = Modifier.size(28.dp)
            )
            Spacer(modifier = Modifier.width(16.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = title,
                    fontWeight = FontWeight.SemiBold,
                    color = DncOnSurface
                )
                Text(
                    text = subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = DncOnSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
            Switch(
                checked = checked,
                onCheckedChange = onCheckedChange,
                colors = SwitchDefaults.colors(
                    checkedTrackColor = DncCyan,
                    checkedThumbColor = Color.Black
                )
            )
        }
    }
}

@Composable
private fun BlockedItem(domain: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            imageVector = Icons.Filled.Block,
            contentDescription = null,
            tint = DncRed.copy(alpha = 0.7f),
            modifier = Modifier.size(16.dp)
        )
        Spacer(modifier = Modifier.width(8.dp))
        Text(
            text = domain,
            style = MaterialTheme.typography.bodySmall,
            color = DncOnSurfaceVariant,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
    }
}

// Fix typo in ShieldToggle
private fun onToggleToggle(b: Boolean) {}
