package com.dnc.ui.theme

import android.app.Activity
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat

// DNC Color Palette — Clean Black/White with Cyan accent
val DncPurple = Color(0xFF6C3CE1)
val DncPurpleDark = Color(0xFF4A1FB8)
val DncCyan = Color(0xFF00E5FF)
val DncCyanDark = Color(0xFF00B8D4)
val DncGreen = Color(0xFF00E676)
val DncRed = Color(0xFFFF1744)
val DncOrange = Color(0xFFFF9100)

// Core palette — black & white dominant
val DncBackground = Color(0xFF000000)       // Pure black
val DncSurface = Color(0xFF0A0A0A)          // Near-black
val DncSurfaceVariant = Color(0xFF1A1A1A)   // Dark gray
val DncOnBackground = Color(0xFFFFFFFF)     // Pure white
val DncOnSurface = Color(0xFFE0E0E0)        // Off-white
val DncOnSurfaceVariant = Color(0xFF888888) // Medium gray

private val DncDarkColorScheme = darkColorScheme(
    primary = DncCyan,
    onPrimary = Color.Black,
    primaryContainer = Color(0xFF001F25),
    onPrimaryContainer = DncCyan,
    secondary = DncPurple,
    onSecondary = Color.White,
    secondaryContainer = DncPurpleDark,
    onSecondaryContainer = Color.White,
    tertiary = DncGreen,
    onTertiary = Color.Black,
    tertiaryContainer = Color(0xFF003D2E),
    onTertiaryContainer = DncGreen,
    error = DncRed,
    onError = Color.White,
    errorContainer = Color(0xFF690005),
    onErrorContainer = Color.White,
    background = DncBackground,
    onBackground = DncOnBackground,
    surface = DncSurface,
    onSurface = DncOnSurface,
    surfaceVariant = DncSurfaceVariant,
    onSurfaceVariant = DncOnSurfaceVariant,
    outline = Color(0xFF333333),
    outlineVariant = Color(0xFF222222),
)

@Composable
fun DncTheme(
    content: @Composable () -> Unit
) {
    val colorScheme = DncDarkColorScheme

    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            window.statusBarColor = DncBackground.toArgb()
            window.navigationBarColor = Color.Black.toArgb()
            WindowCompat.getInsetsController(window, view).isAppearanceLightStatusBars = false
        }
    }

    MaterialTheme(
        colorScheme = colorScheme,
        typography = Typography(),
        content = content
    )
}
