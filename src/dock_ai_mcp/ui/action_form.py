"""
Dynamic Action Form HTML for MCP Apps

This module provides the HTML template for the interactive action form.
The form dynamically renders fields based on the capability's input_schema.
"""

# The HTML is served as a single-file app with embedded CSS and JS
# It implements the MCP Apps protocol using postMessage + JSON-RPC

ACTION_FORM_HTML = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dock AI - Action Form</title>
    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #1a1a2e;
            color: #eee;
            padding: 16px;
            min-height: 100vh;
        }

        .container {
            max-width: 400px;
            margin: 0 auto;
        }

        .header {
            margin-bottom: 20px;
        }

        .header h1 {
            font-size: 18px;
            color: #fff;
            margin-bottom: 4px;
        }

        .header .subtitle {
            font-size: 13px;
            color: #888;
        }

        .form-group {
            margin-bottom: 16px;
        }

        .form-group label {
            display: block;
            font-size: 13px;
            color: #aaa;
            margin-bottom: 6px;
        }

        .form-group label .required {
            color: #ff6b6b;
        }

        .form-group input,
        .form-group textarea,
        .form-group select {
            width: 100%;
            padding: 10px 12px;
            font-size: 14px;
            background: #16213e;
            border: 1px solid #333;
            border-radius: 8px;
            color: #fff;
            transition: border-color 0.2s;
        }

        .form-group input:focus,
        .form-group textarea:focus,
        .form-group select:focus {
            outline: none;
            border-color: #6366f1;
        }

        .form-group textarea {
            min-height: 100px;
            resize: vertical;
        }

        .form-group .hint {
            font-size: 11px;
            color: #666;
            margin-top: 4px;
        }

        .submit-btn {
            width: 100%;
            padding: 12px;
            font-size: 14px;
            font-weight: 600;
            background: linear-gradient(135deg, #6366f1, #8b5cf6);
            color: #fff;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            transition: transform 0.1s, opacity 0.2s;
        }

        .submit-btn:hover {
            transform: translateY(-1px);
        }

        .submit-btn:active {
            transform: translateY(0);
        }

        .submit-btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }

        .status {
            margin-top: 16px;
            padding: 12px;
            border-radius: 8px;
            font-size: 13px;
            display: none;
        }

        .status.success {
            display: block;
            background: rgba(34, 197, 94, 0.1);
            border: 1px solid rgba(34, 197, 94, 0.3);
            color: #22c55e;
        }

        .status.error {
            display: block;
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.3);
            color: #ef4444;
        }

        .status.loading {
            display: block;
            background: rgba(99, 102, 241, 0.1);
            border: 1px solid rgba(99, 102, 241, 0.3);
            color: #6366f1;
        }

        .loading-state {
            text-align: center;
            padding: 40px;
            color: #888;
        }

        .spinner {
            width: 24px;
            height: 24px;
            border: 2px solid #333;
            border-top-color: #6366f1;
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
            margin: 0 auto 12px;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="container">
        <div id="loading" class="loading-state">
            <div class="spinner"></div>
            <div>Loading form...</div>
        </div>

        <div id="form-container" style="display: none;">
            <div class="header">
                <h1 id="entity-name">Contact Business</h1>
                <div class="subtitle" id="action-description">Fill out the form below</div>
            </div>

            <form id="action-form">
                <div id="fields-container"></div>
                <button type="submit" class="submit-btn" id="submit-btn">Submit</button>
            </form>

            <div id="status" class="status"></div>
        </div>
    </div>

    <script>
        (function() {
            "use strict";

            let toolResult = null;
            let entityId = null;
            let actionSlug = null;
            let requestId = 0;
            const pendingRequests = new Map();

            // Listen for messages from the host
            window.addEventListener("message", function(event) {
                const data = event.data;
                if (!data) return;

                // Handle JSON-RPC responses
                if (data.jsonrpc === "2.0") {
                    if (data.id && pendingRequests.has(data.id)) {
                        const handlers = pendingRequests.get(data.id);
                        pendingRequests.delete(data.id);

                        if (data.error) {
                            handlers.reject(new Error(data.error.message || "Unknown error"));
                        } else {
                            handlers.resolve(data.result);
                        }
                    }

                    // Handle tool result notification
                    if (data.method === "notifications/toolResult") {
                        toolResult = data.params;
                        initializeForm();
                    }
                }

                // Handle legacy format (direct result)
                if (data.type === "toolResult" || data.toolResult) {
                    toolResult = data.toolResult || data;
                    initializeForm();
                }
            });

            // Send JSON-RPC request to host
            function sendRequest(method, params) {
                return new Promise(function(resolve, reject) {
                    const id = ++requestId;
                    pendingRequests.set(id, { resolve: resolve, reject: reject });

                    parent.postMessage({
                        jsonrpc: "2.0",
                        id: id,
                        method: method,
                        params: params || {}
                    }, "*");

                    // Timeout after 30s
                    setTimeout(function() {
                        if (pendingRequests.has(id)) {
                            pendingRequests.delete(id);
                            reject(new Error("Request timeout"));
                        }
                    }, 30000);
                });
            }

            // Call a server tool
            function callServerTool(name, args) {
                return sendRequest("tools/call", { name: name, arguments: args });
            }

            // Initialize form when we receive tool result
            function initializeForm() {
                if (!toolResult) return;

                document.getElementById("loading").style.display = "none";
                document.getElementById("form-container").style.display = "block";

                // Extract data from tool result
                const entity = toolResult.entity || {};
                const capability = toolResult.capability || {};
                const inputSchema = capability.input_schema || {};

                entityId = toolResult.entity_id || entity.id;
                actionSlug = toolResult.action;

                // Update header using textContent (safe)
                const entityNameEl = document.getElementById("entity-name");
                entityNameEl.textContent = capability.name || ("Contact " + (entity.name || "Business"));

                const descEl = document.getElementById("action-description");
                descEl.textContent = capability.description || "Fill out the form below";

                // Generate form fields using safe DOM methods
                const container = document.getElementById("fields-container");
                while (container.firstChild) {
                    container.removeChild(container.firstChild);
                }

                const fieldNames = Object.keys(inputSchema);
                for (let i = 0; i < fieldNames.length; i++) {
                    const fieldName = fieldNames[i];
                    const fieldConfig = inputSchema[fieldName];
                    const fieldEl = createFormField(fieldName, fieldConfig);
                    container.appendChild(fieldEl);
                }

                // Update submit button text based on action
                const submitBtn = document.getElementById("submit-btn");
                const actionLabels = {
                    "send_message": "Send Message",
                    "book": "Book Now",
                    "search_catalog": "Search",
                    "get_availability": "Check Availability",
                    "request_quote": "Request Quote",
                    "subscribe": "Subscribe"
                };
                submitBtn.textContent = actionLabels[actionSlug] || "Submit";
            }

            // Create a form field element using safe DOM methods
            function createFormField(name, config) {
                const group = document.createElement("div");
                group.className = "form-group";

                const label = document.createElement("label");
                label.setAttribute("for", name);
                label.textContent = config.label || name;

                if (config.required) {
                    const requiredSpan = document.createElement("span");
                    requiredSpan.className = "required";
                    requiredSpan.textContent = " *";
                    label.appendChild(requiredSpan);
                }

                group.appendChild(label);

                let input;

                // Handle different field types
                if (config.type === "enum" && config.options) {
                    input = document.createElement("select");
                    const defaultOpt = document.createElement("option");
                    defaultOpt.value = "";
                    defaultOpt.textContent = "Select...";
                    input.appendChild(defaultOpt);

                    for (let i = 0; i < config.options.length; i++) {
                        const opt = config.options[i];
                        const option = document.createElement("option");
                        option.value = opt;
                        option.textContent = opt;
                        input.appendChild(option);
                    }
                } else if (config.type === "boolean") {
                    input = document.createElement("select");
                    var opts = [
                        { value: "", text: "Select..." },
                        { value: "true", text: "Yes" },
                        { value: "false", text: "No" }
                    ];
                    for (var j = 0; j < opts.length; j++) {
                        var option = document.createElement("option");
                        option.value = opts[j].value;
                        option.textContent = opts[j].text;
                        input.appendChild(option);
                    }
                } else if (name === "message" || config.multiline) {
                    input = document.createElement("textarea");
                    input.placeholder = config.placeholder || ("Enter " + (config.label || name) + "...");
                } else {
                    input = document.createElement("input");

                    // Set input type based on format
                    var typeMap = {
                        "email": "email",
                        "date": "date",
                        "time": "time",
                        "datetime": "datetime-local",
                        "phone": "tel",
                        "url": "url",
                        "number": "number"
                    };
                    input.type = typeMap[config.format] || typeMap[config.type] || "text";
                    input.placeholder = config.placeholder || ("Enter " + (config.label || name) + "...");
                }

                input.id = name;
                input.name = name;
                if (config.required) input.required = true;

                group.appendChild(input);

                // Add hint if available
                var hintText = config.aiDescription || config.ai_description;
                if (hintText) {
                    var hint = document.createElement("div");
                    hint.className = "hint";
                    hint.textContent = hintText;
                    group.appendChild(hint);
                }

                return group;
            }

            // Handle form submission
            document.getElementById("action-form").addEventListener("submit", function(e) {
                e.preventDefault();

                var submitBtn = document.getElementById("submit-btn");
                var statusEl = document.getElementById("status");

                // Collect form data
                var formData = new FormData(e.target);
                var params = {};

                formData.forEach(function(value, key) {
                    if (value) {
                        // Convert boolean strings
                        if (value === "true") params[key] = true;
                        else if (value === "false") params[key] = false;
                        else params[key] = value;
                    }
                });

                // Show loading state
                submitBtn.disabled = true;
                submitBtn.textContent = "Sending...";
                statusEl.className = "status loading";
                statusEl.textContent = "Processing your request...";

                // Call execute_action via the host
                callServerTool("execute_action", {
                    entity_id: entityId,
                    action: actionSlug,
                    params: params
                }).then(function(result) {
                    // Show success
                    statusEl.className = "status success";
                    statusEl.textContent = result.message || result._ai_hint || "Action completed successfully!";
                    submitBtn.textContent = "Done!";
                }).catch(function(error) {
                    // Show error
                    statusEl.className = "status error";
                    statusEl.textContent = error.message || "Something went wrong. Please try again.";
                    submitBtn.disabled = false;
                    submitBtn.textContent = "Retry";
                });
            });

            // Signal that the app is ready
            parent.postMessage({
                jsonrpc: "2.0",
                method: "notifications/ready",
                params: { name: "Dock AI Action Form", version: "1.0.0" }
            }, "*");

            // Timeout if we don't receive tool result
            setTimeout(function() {
                if (!toolResult) {
                    var loadingEl = document.getElementById("loading");
                    while (loadingEl.firstChild) {
                        loadingEl.removeChild(loadingEl.firstChild);
                    }
                    var errorDiv = document.createElement("div");
                    errorDiv.style.color = "#ef4444";
                    errorDiv.textContent = "Unable to load form data.";
                    loadingEl.appendChild(errorDiv);

                    var hintDiv = document.createElement("div");
                    hintDiv.style.marginTop = "8px";
                    hintDiv.style.fontSize = "12px";
                    hintDiv.textContent = "The host may not support MCP Apps yet.";
                    loadingEl.appendChild(hintDiv);
                }
            }, 5000);
        })();
    </script>
</body>
</html>
'''
