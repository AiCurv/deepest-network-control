package com.dnc.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.shrinkVertically
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
import com.dnc.filter.FilterEngine
import com.dnc.filter.FilterRule
import com.dnc.filter.FilterRuleType
import com.dnc.handler.ResourceRegistry
import com.dnc.scriptlet.ScriptletEngine
import com.dnc.ui.theme.*

/**
 * Custom Script Editor screen — the uBlock Origin "My Rules" equivalent.
 *
 * Features:
 * - Write custom filter rules (||ads.com^, @@||safe.com^, etc.)
 * - Write custom scriptlet injection rules (domain##+js(scriptlet-name))
 * - Write custom cosmetic rules (domain##.ad-banner)
 * - Write $removeparam rules (||tracker.com^$removeparam=utm_source)
 * - Write $csp rules (||example.com^$csp=default-src 'none')
 * - Write $redirect rules (||ads.com/banner$redirect=1x1.gif)
 * - Browse available scriptlets and their documentation
 * - Browse redirect resources
 * - Template insertion for common rule patterns
 * - Syntax validation feedback
 */
@Composable
fun ScriptEditorScreen(
    filterEngine: FilterEngine
) {
    var editorText by remember { mutableStateOf("") }
    var selectedTab by remember { mutableStateOf(EditorTab.RULES) }
    var showTemplates by remember { mutableStateOf(false) }
    var validationError by remember { mutableStateOf<String?>(null) }
    var validationSuccess by remember { mutableStateOf(false) }

    val scriptletEngine = ScriptletEngine.getInstance()
    val resourceRegistry = ResourceRegistry.getInstance()
    val customRules = filterEngine.getCustomRules()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        // Header
        Text(
            text = "SCRIPT EDITOR",
            style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.Bold,
            color = DncCyan
        )
        Text(
            text = "Write custom filter rules, scriptlets, and cosmetic filters",
            style = MaterialTheme.typography.bodySmall,
            color = DncOnSurfaceVariant
        )

        Spacer(modifier = Modifier.height(12.dp))

        // Tab Row
        ScrollableTabRow(
            selectedTabIndex = selectedTab.ordinal,
            containerColor = DncSurfaceVariant,
            contentColor = DncCyan,
            edgePadding = 0.dp
        ) {
            EditorTab.entries.forEach { tab ->
                Tab(
                    selected = selectedTab == tab,
                    onClick = { selectedTab = tab },
                    text = {
                        Text(
                            tab.label,
                            color = if (selectedTab == tab) DncCyan else DncOnSurfaceVariant,
                            fontWeight = if (selectedTab == tab) FontWeight.Bold else FontWeight.Normal,
                            fontSize = 12.sp
                        )
                    }
                )
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        when (selectedTab) {
            EditorTab.RULES -> {
                // Rule editor
                RuleEditor(
                    text = editorText,
                    onTextChange = { editorText = it },
                    onAdd = {
                        if (editorText.isNotBlank()) {
                            val rule = filterEngine.addCustomRule(editorText.trim())
                            if (rule != null) {
                                validationError = null
                                validationSuccess = true
                                editorText = ""
                            } else {
                                validationError = "Invalid rule syntax"
                                validationSuccess = false
                            }
                        }
                    },
                    validationError = validationError,
                    validationSuccess = validationSuccess,
                    onClearValidation = {
                        validationError = null
                        validationSuccess = false
                    },
                    showTemplates = showTemplates,
                    onToggleTemplates = { showTemplates = !showTemplates }
                )
            }
            EditorTab.SCRIPTLETS -> {
                ScriptletBrowser(scriptletEngine = scriptletEngine, onInsert = { template ->
                    editorText = template
                    selectedTab = EditorTab.RULES
                })
            }
            EditorTab.RESOURCES -> {
                ResourceBrowser(resourceRegistry = resourceRegistry)
            }
            EditorTab.MY_RULES -> {
                MyRulesList(rules = customRules, onDelete = { ruleText ->
                    filterEngine.removeCustomRule(ruleText)
                })
            }
        }
    }
}

enum class EditorTab(val label: String) {
    RULES("Editor"),
    SCRIPTLETS("Scriptlets"),
    RESOURCES("Resources"),
    MY_RULES("My Rules")
}

@Composable
private fun RuleEditor(
    text: String,
    onTextChange: (String) -> Unit,
    onAdd: () -> Unit,
    validationError: String?,
    validationSuccess: Boolean,
    onClearValidation: () -> Unit,
    showTemplates: Boolean,
    onToggleTemplates: () -> Unit
) {
    Column {
        // Editor field
        OutlinedTextField(
            value = text,
            onValueChange = {
                onTextChange(it)
                onClearValidation()
            },
            placeholder = {
                Text(
                    "||ads.example.com^\n@@||safe-site.com^\nexample.com##+js(no-xhr-if, tracker)\nexample.com##.ad-banner\n||tracker.com^\$removeparam=utm_*",
                    fontFamily = FontFamily.Monospace,
                    fontSize = 12.sp,
                    color = DncOnSurfaceVariant.copy(alpha = 0.5f)
                )
            },
            modifier = Modifier
                .fillMaxWidth()
                .height(160.dp),
            shape = RoundedCornerShape(12.dp),
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = DncCyan,
                unfocusedBorderColor = DncOnSurfaceVariant,
                cursorColor = DncCyan,
                focusedTextColor = DncOnSurface,
                unfocusedTextColor = DncOnSurface
            ),
            textStyle = LocalTextStyle.current.copy(
                fontFamily = FontFamily.Monospace,
                fontSize = 13.sp
            )
        )

        // Validation feedback
        AnimatedVisibility(
            visible = validationError != null,
            enter = expandVertically(),
            exit = shrinkVertically()
        ) {
            Text(
                text = validationError ?: "",
                color = DncRed,
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(top = 4.dp)
            )
        }
        AnimatedVisibility(
            visible = validationSuccess,
            enter = expandVertically(),
            exit = shrinkVertically()
        ) {
            Text(
                text = "Rule added successfully",
                color = DncGreen,
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(top = 4.dp)
            )
        }

        Spacer(modifier = Modifier.height(8.dp))

        // Action buttons
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Button(
                onClick = onAdd,
                modifier = Modifier.weight(1f),
                shape = RoundedCornerShape(12.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = DncCyan,
                    contentColor = Color.Black
                )
            ) {
                Icon(Icons.Filled.Add, "Add", modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(4.dp))
                Text("Add Rule", fontWeight = FontWeight.Bold, fontSize = 13.sp)
            }

            OutlinedButton(
                onClick = onToggleTemplates,
                shape = RoundedCornerShape(12.dp),
                colors = ButtonDefaults.outlinedButtonColors(
                    contentColor = DncPurple
                ),
                border = androidx.compose.foundation.BorderStroke(1.dp, DncPurple)
            ) {
                Icon(
                    Icons.Filled.Code,
                    "Templates",
                    modifier = Modifier.size(18.dp),
                    tint = DncPurple
                )
                Spacer(modifier = Modifier.width(4.dp))
                Text("Templates", fontSize = 13.sp)
            }
        }

        // Templates panel
        AnimatedVisibility(
            visible = showTemplates,
            enter = expandVertically(),
            exit = shrinkVertically()
        ) {
            TemplatePanel(onInsert = { template ->
                onTextChange(template)
                onToggleTemplates()
            })
        }
    }
}

@Composable
private fun TemplatePanel(onInsert: (String) -> Unit) {
    val templates = listOf(
        "Block domain" to "||ads.example.com^",
        "Allow domain" to "@@||safe-site.com^",
        "Block with options" to "||tracker.com^\$script,third-party",
        "Important block" to "||critical-tracker.com^\$important",
        "Remove param" to "||site.com^\$removeparam=utm_*",
        "CSP inject" to "||example.com^\$csp=default-src 'self'",
        "Redirect to pixel" to "||ads.com/banner.jpg\$redirect=1x1.gif",
        "Redirect to blank JS" to "||tracker.com/track.js\$redirect=blank.js",
        "Cosmetic hide" to "example.com##.ad-banner",
        "Cosmetic exception" to "example.com#@#.ad-banner",
        "Scriptlet: abort-on-property-read" to "example.com##+js(abort-on-property-read, navigator.userAgent)",
        "Scriptlet: set-constant" to "example.com##+js(set-constant, navigator.webdriver, false)",
        "Scriptlet: no-xhr-if" to "example.com##+js(no-xhr-if, /analytics/)",
        "Scriptlet: no-fetch-if" to "example.com##+js(no-fetch-if, /tracker/)",
        "Scriptlet: cookie-remover" to "example.com##+js(cookie-remover, _ga)",
        "Scriptlet: remove-class" to "example.com##+js(remove-class, ad-visible)",
        "Scriptlet: json-prune" to "example.com##+js(json-prune, ads.adSlots)"
    )

    Card(
        modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = DncSurfaceVariant)
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Text(
                "RULE TEMPLATES",
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Bold,
                color = DncPurple
            )
            Spacer(modifier = Modifier.height(8.dp))

            templates.forEach { (name, template) ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 2.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = name,
                        modifier = Modifier.weight(1f),
                        style = MaterialTheme.typography.bodySmall,
                        color = DncOnSurface,
                        fontWeight = FontWeight.Medium
                    )
                    IconButton(
                        onClick = { onInsert(template) },
                        modifier = Modifier.size(28.dp)
                    ) {
                        Icon(
                            Icons.Filled.ContentCopy,
                            "Use template",
                            tint = DncCyan,
                            modifier = Modifier.size(16.dp)
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun ScriptletBrowser(
    scriptletEngine: ScriptletEngine,
    onInsert: (String) -> Unit
) {
    val scriptlets = remember { scriptletEngine.getRegisteredScriptlets().distinctBy { it } }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        item {
            Text(
                "AVAILABLE SCRIPTLETS",
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Bold,
                color = DncPurple
            )
            Text(
                "Tap to insert a ##+js() rule template",
                style = MaterialTheme.typography.bodySmall,
                color = DncOnSurfaceVariant
            )
            Spacer(modifier = Modifier.height(8.dp))
        }

        items(scriptlets) { name ->
            val def = scriptletEngine.getScriptlet(name)
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(10.dp),
                colors = CardDefaults.cardColors(containerColor = DncSurfaceVariant)
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "##+js($name)",
                            fontFamily = FontFamily.Monospace,
                            fontSize = 12.sp,
                            color = DncCyan,
                            fontWeight = FontWeight.Bold
                        )
                        if (def != null) {
                            Text(
                                text = def.description,
                                style = MaterialTheme.typography.bodySmall,
                                color = DncOnSurfaceVariant,
                                maxLines = 2,
                                overflow = TextOverflow.Ellipsis
                            )
                            if (def.minArgs > 0) {
                                Text(
                                    text = "Args: ${def.minArgs}-${def.maxArgs}" +
                                            if (def.requiresTrust) " (trusted)" else "",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = DncOrange
                                )
                            }
                        }
                    }
                    IconButton(onClick = { onInsert("##+js($name)") }) {
                        Icon(Icons.Filled.Add, "Insert", tint = DncGreen, modifier = Modifier.size(20.dp))
                    }
                }
            }
        }
    }
}

@Composable
private fun ResourceBrowser(resourceRegistry: ResourceRegistry) {
    val resources = remember { resourceRegistry.getAllResources().distinctBy { it.name } }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        item {
            Text(
                "REDIRECT RESOURCES",
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Bold,
                color = DncPurple
            )
            Text(
                "Available resources for \$redirect= rules",
                style = MaterialTheme.typography.bodySmall,
                color = DncOnSurfaceVariant
            )
            Spacer(modifier = Modifier.height(8.dp))
        }

        items(resources) { resource ->
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(10.dp),
                colors = CardDefaults.cardColors(containerColor = DncSurfaceVariant)
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        when {
                            resource.contentType.startsWith("image/") -> Icons.Filled.Image
                            resource.contentType.contains("javascript") -> Icons.Filled.Code
                            resource.contentType.contains("html") -> Icons.Filled.Language
                            resource.contentType.contains("css") -> Icons.Filled.Brush
                            else -> Icons.Filled.Description
                        },
                        contentDescription = null,
                        tint = DncCyan,
                        modifier = Modifier.size(24.dp)
                    )
                    Spacer(modifier = Modifier.width(12.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "\$redirect=${resource.name}",
                            fontFamily = FontFamily.Monospace,
                            fontSize = 12.sp,
                            color = DncGreen,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = resource.description,
                            style = MaterialTheme.typography.bodySmall,
                            color = DncOnSurfaceVariant
                        )
                        Text(
                            text = "${resource.contentType} · ${resource.data.size} bytes",
                            style = MaterialTheme.typography.labelSmall,
                            color = DncOnSurfaceVariant
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun MyRulesList(
    rules: List<FilterRule>,
    onDelete: (String) -> Unit
) {
    if (rules.isEmpty()) {
        Box(
            modifier = Modifier.fillMaxSize(),
            contentAlignment = Alignment.Center
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Icon(
                    Icons.Filled.EditNote,
                    contentDescription = null,
                    tint = DncOnSurfaceVariant,
                    modifier = Modifier.size(64.dp)
                )
                Spacer(modifier = Modifier.height(16.dp))
                Text(
                    "No custom rules yet",
                    style = MaterialTheme.typography.bodyLarge,
                    color = DncOnSurfaceVariant
                )
                Text(
                    "Use the Editor tab to add rules",
                    style = MaterialTheme.typography.bodySmall,
                    color = DncOnSurfaceVariant
                )
            }
        }
        return
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        item {
            Text(
                "${rules.size} CUSTOM RULES",
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Bold,
                color = DncPurple
            )
            Spacer(modifier = Modifier.height(8.dp))
        }

        items(rules) { rule ->
            val ruleColor = when (rule.type) {
                FilterRuleType.BLOCK -> DncRed
                FilterRuleType.EXCEPTION -> DncGreen
                FilterRuleType.COSMETIC -> DncOrange
                FilterRuleType.COSMETIC_EXCEPTION -> DncCyan
                FilterRuleType.SCRIPTLET -> DncPurple
                FilterRuleType.REDIRECT -> Color.Magenta
                else -> DncOnSurfaceVariant
            }

            val typeLabel = when (rule.type) {
                FilterRuleType.BLOCK -> "BLOCK"
                FilterRuleType.EXCEPTION -> "ALLOW"
                FilterRuleType.COSMETIC -> "HIDE"
                FilterRuleType.COSMETIC_EXCEPTION -> "SHOW"
                FilterRuleType.SCRIPTLET -> "SCRIPTLET"
                FilterRuleType.REDIRECT -> "REDIRECT"
                FilterRuleType.HEADER -> "HEADER"
                FilterRuleType.HTML_FILTER -> "HTML"
                FilterRuleType.COMMENT -> "COMMENT"
            }

            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(10.dp),
                colors = CardDefaults.cardColors(containerColor = DncSurfaceVariant.copy(alpha = 0.7f))
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(10.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    // Type badge
                    Box(
                        modifier = Modifier
                            .background(ruleColor.copy(alpha = 0.2f), RoundedCornerShape(4.dp))
                            .padding(horizontal = 6.dp, vertical = 2.dp)
                    ) {
                        Text(
                            text = typeLabel,
                            fontSize = 9.sp,
                            fontWeight = FontWeight.Bold,
                            color = ruleColor
                        )
                    }

                    Spacer(modifier = Modifier.width(8.dp))

                    Text(
                        text = rule.rawText,
                        modifier = Modifier.weight(1f),
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        color = DncOnSurface,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis,
                        fontSize = 11.sp
                    )

                    IconButton(
                        onClick = { onDelete(rule.rawText) },
                        modifier = Modifier.size(28.dp)
                    ) {
                        Icon(
                            Icons.Filled.Delete,
                            "Delete",
                            tint = DncRed.copy(alpha = 0.7f),
                            modifier = Modifier.size(16.dp)
                        )
                    }
                }
            }
        }
    }
}
