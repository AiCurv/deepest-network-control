package com.dnc.ui.screens

import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.navigation.NavDestination.Companion.hierarchy
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
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
    val filterEngine = FilterEngine.getInstance()
    val stats by remember { mutableStateOf(filterEngine.getStats()) }
    val blockedCount by DncVpnService.blockedCount.collectAsState()
    val dnsQueryCount by DncVpnService.dnsQueryCount.collectAsState()
    val redirectsBlocked by DncVpnService.redirectsBlockedCount.collectAsState()

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
                    recentBlocked = listOf(
                        "ads.google.com",
                        "tracker.facebook.net",
                        "doubleclick.net",
                        "adservice.google.com",
                        "analytics.google.com"
                    ),
                    httpsFilteringEnabled = false,
                    onHttpsFilteringChanged = { /* TODO: wire to HttpsProxy */ }
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
                    onInstallCaCert = { /* TODO: wire to CertificateManager */ },
                    isCaInstalled = false,
                    httpsFilteringEnabled = false,
                    onHttpsFilteringChanged = { /* TODO: wire to HttpsProxy */ }
                )
            }
        }
    }
}
