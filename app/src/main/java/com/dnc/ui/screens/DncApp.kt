package com.dnc.ui.screens

import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.navigation.NavDestination.Companion.hierarchy
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.dnc.cert.CertificateManager
import com.dnc.filter.FilterEngine
import com.dnc.proxy.HttpProxy
import com.dnc.vpn.DncVpnService
import com.dnc.ui.theme.*

sealed class Screen(val route: String, val label: String, val icon: ImageVector) {
    data object Dashboard : Screen("dashboard", "Dashboard", Icons.Filled.Shield)
    data object Filters : Screen("filters", "Filters", Icons.Filled.FilterList)
    data object ScriptEditor : Screen("scripts", "Scripts", Icons.Filled.Code)
    data object Log : Screen("log", "Log", Icons.Filled.List)
    data object Settings : Screen("settings", "Settings", Icons.Filled.Settings)
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DncApp(
    onVpnToggle: (Boolean) -> Unit
) {
    val navController = rememberNavController()
    val isVpnActive by DncVpnService.isRunning.collectAsState()
    val blockedCount by DncVpnService.blockedCount.collectAsState()
    val dnsQueryCount by DncVpnService.dnsQueryCount.collectAsState()
    val redirectsBlocked by DncVpnService.redirectsBlockedCount.collectAsState()

    // Get context for CertificateManager
    val context = LocalContext.current

    // Get filter engine stats
    val filterEngine = remember { FilterEngine.getInstance() }
    var stats by remember { mutableStateOf(filterEngine.getStats()) }

    // Update stats periodically when VPN is active
    LaunchedEffect(isVpnActive) {
        while (isVpnActive) {
            kotlinx.coroutines.delay(2000)
            stats = filterEngine.getStats()
        }
    }

    // Track HTTPS filtering state
    var httpsFilteringEnabled by remember { mutableStateOf(false) }

    // Track CA certificate installation status
    var isCaInstalled by remember { mutableStateOf(false) }

    // Check CA install status periodically
    LaunchedEffect(Unit) {
        while (true) {
            try {
                val certManager = CertificateManager.getInstance(context)
                isCaInstalled = certManager.isCaInstalled()
            } catch (_: Exception) {}
            kotlinx.coroutines.delay(3000)
        }
    }

    val screens = listOf(
        Screen.Dashboard,
        Screen.Filters,
        Screen.ScriptEditor,
        Screen.Log,
        Screen.Settings
    )

    Scaffold(
        bottomBar = {
            NavigationBar(
                containerColor = DncSurface,
                contentColor = DncOnSurface
            ) {
                val navBackStackEntry by navController.currentBackStackEntryAsState()
                val currentDestination = navBackStackEntry?.destination

                screens.forEach { screen ->
                    NavigationBarItem(
                        icon = {
                            Icon(
                                screen.icon,
                                contentDescription = screen.label,
                                tint = if (currentDestination?.hierarchy?.any { it.route == screen.route } == true)
                                    DncCyan else DncOnSurfaceVariant
                            )
                        },
                        label = {
                            Text(
                                screen.label,
                                color = if (currentDestination?.hierarchy?.any { it.route == screen.route } == true)
                                    DncCyan else DncOnSurfaceVariant,
                                fontSize = androidx.compose.ui.unit.TextUnit.Unspecified
                            )
                        },
                        selected = currentDestination?.hierarchy?.any { it.route == screen.route } == true,
                        onClick = {
                            navController.navigate(screen.route) {
                                popUpTo(navController.graph.findStartDestination().id) {
                                    saveState = true
                                }
                                launchSingleTop = true
                                restoreState = true
                            }
                        }
                    )
                }
            }
        }
    ) { innerPadding ->
        NavHost(
            navController = navController,
            startDestination = Screen.Dashboard.route,
            modifier = Modifier.padding(innerPadding)
        ) {
            composable(Screen.Dashboard.route) {
                DashboardScreen(
                    isVpnActive = isVpnActive,
                    onVpnToggle = onVpnToggle,
                    blockedCount = blockedCount,
                    dnsQueryCount = dnsQueryCount,
                    redirectsBlocked = redirectsBlocked,
                    activeRulesCount = stats.totalRules,
                    recentBlocked = emptyList(),
                    httpsFilteringEnabled = httpsFilteringEnabled,
                    onHttpsFilteringChanged = { enabled ->
                        httpsFilteringEnabled = enabled
                    }
                )
            }

            composable(Screen.Filters.route) {
                FilterListsScreen(filterEngine = filterEngine)
            }

            composable(Screen.ScriptEditor.route) {
                ScriptEditorScreen(filterEngine = filterEngine)
            }

            composable(Screen.Log.route) {
                LogScreen(logEntries = emptyList())
            }

            composable(Screen.Settings.route) {
                SettingsScreen(
                    onInstallCaCert = {
                        // Wire to CertificateManager
                        try {
                            val certManager = CertificateManager.getInstance(context)
                            certManager.installCaCertificate()
                            // Don't mark as installed here — the user still needs to
                            // confirm in the system dialog. The periodic check will
                            // detect when the CA is actually trusted.
                        } catch (e: Exception) {
                            android.util.Log.e("DncApp", "Failed to install CA cert: ${e.message}")
                        }
                    },
                    isCaInstalled = isCaInstalled,
                    httpsFilteringEnabled = httpsFilteringEnabled,
                    onHttpsFilteringChanged = { enabled ->
                        httpsFilteringEnabled = enabled
                    }
                )
            }
        }
    }
}
