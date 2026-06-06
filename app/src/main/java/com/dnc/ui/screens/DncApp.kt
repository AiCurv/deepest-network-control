package com.dnc.ui.screens

import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
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

    // Collect VPN stats
    val blockedCount by DncVpnService.Companion.let {
        // Access through the service — simplified for UI
        mutableStateOf(0)
    }

    val screens = listOf(
        Screen.Dashboard,
        Screen.Filters,
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
                                    DncCyan else DncOnSurfaceVariant
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
                    blockedCount = stats.blockedRequests.toInt(),
                    dnsQueryCount = 0,
                    redirectsBlocked = 0,
                    activeRulesCount = stats.totalRules,
                    recentBlocked = listOf(
                        "ads.google.com",
                        "tracker.facebook.net",
                        "doubleclick.net",
                        "adservice.google.com",
                        "analytics.google.com"
                    )
                )
            }

            composable(Screen.Filters.route) {
                FilterListsScreen(filterEngine = filterEngine)
            }

            composable(Screen.Log.route) {
                LogScreen(logEntries = emptyList())
            }

            composable(Screen.Settings.route) {
                SettingsScreen(
                    onInstallCaCert = { /* Will be wired to CertificateManager */ },
                    isCaInstalled = false
                )
            }
        }
    }
}
