package com.dnc.ui.theme

import android.app.Activity
import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat

// DNC Color Palette — Dark, Cyberpunk-ish
val DncPurple = Color(0xFF6C3CE1)
val DncPurpleDark = Color(0xFF4A1FB8)
val DncCyan = Color(0xFF00E5FF)
val DncCyanDark = Color(0xFF00B8D4)
val DncGreen = Color(0xFF00E676)
val DncRed = Color(0xFFFF1744)
val DncOrange = Color(0xFFFF9100)
val DncBackground = Color(0xFF0D0D1A)
val DncSurface = Color(0xFF1A1A2E)
val DncSurfaceVariant = Color(0xFF252540)
val DncOnBackground = Color(0xFFE8E8F0)
val DncOnSurface = Color(0xFFD0D0E0)
val DncOnSurfaceVariant = Color(0xFF9090A8)

private val DncDarkColorScheme = darkColorScheme(
    primary = DncCyan,
    onPrimary = Color.Black,
    primaryContainer = DncPurple,
    onPrimaryContainer = Color.White,
    secondary = DncPurple,
    onSecondary = Color.White,
    secondaryContainer = DncPurpleDark,
    onSecondaryContainer = Color.White,
    tertiary = DncGreen,
    onTertiary = Color.Black,
    tertiaryContainer = Color(0xFF004D40),
    onTertiaryContainer = DncGreen,
    error = DncRed,
    onError = Color.White,
    errorContainer = Color(0xFF7F0000),
    onErrorContainer = Color.White,
    background = DncBackground,
    onBackground = DncOnBackground,
    surface = DncSurface,
    onSurface = DncOnSurface,
    surfaceVariant = DncSurfaceVariant,
    onSurfaceVariant = DncOnSurfaceVariant,
    outline = Color(0xFF404060),
    outlineVariant = Color(0xFF303050),
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
            window.navigationBarColor = DncSurface.toArgb()
            WindowCompat.getInsetsController(window, view).isAppearanceLightStatusBars = false
        }
    }

    MaterialTheme(
        colorScheme = colorScheme,
        typography = Typography(),
        content = content
    )
}
