<?php
// Simple password protection
$ADMIN_PASSWORD = 'healthmonitor2025'; // Change this!

session_start();

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['password'])) {
    if ($_POST['password'] === $ADMIN_PASSWORD) {
        $_SESSION['admin_authenticated'] = true;
    } else {
        $error = 'Invalid password';
    }
}

if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: admin.php');
    exit;
}

if (!isset($_SESSION['admin_authenticated'])) {
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <title>Admin Login</title>
        <style>
            body { font-family: Arial; background: #1a1a2e; color: #fff; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
            .login-box { background: #16213e; padding: 30px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
            input { padding: 10px; width: 250px; border: 1px solid #0f3460; background: #0f3460; color: #fff; border-radius: 4px; }
            button { padding: 10px 20px; background: #e94560; color: #fff; border: none; border-radius: 4px; cursor: pointer; margin-top: 10px; }
            button:hover { background: #c23b52; }
            .error { color: #e94560; margin-top: 10px; }
        </style>
    </head>
    <body>
        <div class="login-box">
            <h2>🔒 Admin Panel</h2>
            <form method="post">
                <input type="password" name="password" placeholder="Enter password" autofocus>
                <br>
                <button type="submit">Login</button>
            </form>
            <?php if (isset($error)) echo "<div class='error'>$error</div>"; ?>
        </div>
    </body>
    </html>
    <?php
    exit;
}

// Get current directory
$currentDir = __DIR__;

// Handle AJAX commands
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    header('Content-Type: application/json');

    $action = $_POST['action'];
    $output = '';
    $exitCode = 0;

    // Change to current directory for all commands
    chdir($currentDir);

    switch ($action) {
        case 'npm_install':
            exec('npm install 2>&1', $output, $exitCode);
            break;

        case 'npm_install_pm2':
            exec('npm install pm2 2>&1', $output, $exitCode);
            break;

        case 'pm2_start':
            exec('./node_modules/.bin/pm2 start scheduler.js --name url-health-monitor 2>&1', $output, $exitCode);
            break;

        case 'pm2_stop':
            exec('./node_modules/.bin/pm2 stop url-health-monitor 2>&1', $output, $exitCode);
            break;

        case 'pm2_restart':
            exec('./node_modules/.bin/pm2 restart url-health-monitor 2>&1', $output, $exitCode);
            break;

        case 'pm2_delete':
            exec('./node_modules/.bin/pm2 delete url-health-monitor 2>&1', $output, $exitCode);
            break;

        case 'pm2_status':
            exec('./node_modules/.bin/pm2 status 2>&1', $output, $exitCode);
            break;

        case 'pm2_logs':
            exec('./node_modules/.bin/pm2 logs url-health-monitor --lines 50 --nostream 2>&1', $output, $exitCode);
            break;

        case 'pm2_save':
            exec('./node_modules/.bin/pm2 save 2>&1', $output, $exitCode);
            break;

        case 'check_files':
            $files = ['scheduler.js', 'package.json', 'index.html'];
            $fileStatus = [];
            foreach ($files as $file) {
                $fileStatus[$file] = file_exists($currentDir . '/' . $file);
            }
            echo json_encode(['success' => true, 'files' => $fileStatus, 'dir' => $currentDir]);
            exit;

        default:
            echo json_encode(['success' => false, 'output' => 'Unknown action']);
            exit;
    }

    echo json_encode([
        'success' => $exitCode === 0,
        'output' => implode("\n", $output),
        'exitCode' => $exitCode
    ]);
    exit;
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Health Monitor Admin Panel</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #1a1a2e;
            color: #e9e9e9;
            padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 {
            color: #e94560;
            margin-bottom: 10px;
            font-size: 28px;
        }
        .header {
            background: #16213e;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        }
        .current-dir {
            font-size: 12px;
            color: #a0a0a0;
            font-family: monospace;
            margin-top: 8px;
        }
        .logout {
            float: right;
            background: #e94560;
            color: white;
            padding: 8px 16px;
            border-radius: 4px;
            text-decoration: none;
            font-size: 14px;
        }
        .logout:hover { background: #c23b52; }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        .card {
            background: #16213e;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        }
        .card h2 {
            color: #e94560;
            font-size: 18px;
            margin-bottom: 15px;
            border-bottom: 2px solid #0f3460;
            padding-bottom: 8px;
        }
        .btn {
            background: #0f3460;
            color: white;
            border: none;
            padding: 10px 16px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            margin: 5px 5px 5px 0;
            transition: all 0.3s;
        }
        .btn:hover { background: #1a4d7a; }
        .btn:disabled { background: #555; cursor: not-allowed; opacity: 0.5; }
        .btn-primary { background: #e94560; }
        .btn-primary:hover { background: #c23b52; }
        .btn-success { background: #28a745; }
        .btn-success:hover { background: #218838; }
        .btn-danger { background: #dc3545; }
        .btn-danger:hover { background: #c82333; }
        .output-box {
            background: #0f0f0f;
            border: 1px solid #0f3460;
            border-radius: 4px;
            padding: 15px;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            max-height: 400px;
            overflow-y: auto;
            margin-top: 15px;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        .output-box:empty::before {
            content: 'Output will appear here...';
            color: #666;
            font-style: italic;
        }
        .status-indicator {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            margin-right: 8px;
        }
        .status-online { background: #28a745; }
        .status-offline { background: #dc3545; }
        .status-unknown { background: #ffc107; }
        .file-check {
            margin: 8px 0;
            padding: 8px;
            background: #0f3460;
            border-radius: 4px;
            font-size: 13px;
        }
        .file-exists { color: #28a745; }
        .file-missing { color: #dc3545; }
        .spinner {
            display: inline-block;
            width: 14px;
            height: 14px;
            border: 2px solid rgba(255,255,255,0.3);
            border-top-color: #e94560;
            border-radius: 50%;
            animation: spin 0.6s linear infinite;
            margin-left: 8px;
            vertical-align: middle;
        }
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <a href="?logout" class="logout">Logout</a>
            <h1>🛠️ Health Monitor Admin Panel</h1>
            <div class="current-dir">📁 Current Directory: <?php echo $currentDir; ?></div>
        </div>

        <div class="grid">
            <!-- File Check Card -->
            <div class="card">
                <h2>📦 File Check</h2>
                <button class="btn btn-primary" onclick="checkFiles()">Check Required Files</button>
                <div id="fileCheckOutput" class="output-box" style="max-height: 200px;"></div>
            </div>

            <!-- NPM Management Card -->
            <div class="card">
                <h2>📦 NPM Management</h2>
                <button class="btn" onclick="runCommand('npm_install')">Install Dependencies</button>
                <button class="btn" onclick="runCommand('npm_install_pm2')">Install PM2</button>
                <div id="npmOutput" class="output-box"></div>
            </div>

            <!-- PM2 Management Card -->
            <div class="card">
                <h2>⚙️ Process Management</h2>
                <button class="btn btn-success" onclick="runCommand('pm2_start')">▶️ Start</button>
                <button class="btn btn-danger" onclick="runCommand('pm2_stop')">⏸️ Stop</button>
                <button class="btn btn-primary" onclick="runCommand('pm2_restart')">🔄 Restart</button>
                <button class="btn btn-danger" onclick="runCommand('pm2_delete')">🗑️ Delete</button>
                <button class="btn" onclick="runCommand('pm2_save')">💾 Save</button>
                <div id="pm2Output" class="output-box"></div>
            </div>
        </div>

        <!-- Status and Logs Full Width -->
        <div class="card">
            <h2>📊 Status & Logs</h2>
            <button class="btn btn-primary" onclick="runCommand('pm2_status')">Check Status</button>
            <button class="btn" onclick="runCommand('pm2_logs')">View Logs (Last 50 lines)</button>
            <button class="btn" onclick="refreshLogs()" id="autoRefreshBtn">🔄 Auto-refresh OFF</button>
            <div id="statusOutput" class="output-box"></div>
        </div>

        <!-- Quick Deploy Guide -->
        <div class="card">
            <h2>🚀 Quick Deploy Guide</h2>
            <div style="color: #a0a0a0; font-size: 14px; line-height: 1.6;">
                <ol style="margin-left: 20px;">
                    <li>Upload files: <code>scheduler.js</code>, <code>package.json</code>, <code>index.html</code>, and <code>api/</code> folder</li>
                    <li>Click <strong>"Check Required Files"</strong> to verify</li>
                    <li>Click <strong>"Install Dependencies"</strong></li>
                    <li>Click <strong>"Install PM2"</strong></li>
                    <li>Click <strong>"▶️ Start"</strong> to start the scheduler</li>
                    <li>Click <strong>"Check Status"</strong> to verify it's running</li>
                    <li>Click <strong>"View Logs"</strong> to see output</li>
                </ol>
                <div style="margin-top: 15px; padding: 10px; background: #0f3460; border-radius: 4px;">
                    💡 <strong>Tip:</strong> This admin panel works from any folder - just upload it alongside your files!
                </div>
            </div>
        </div>
    </div>

    <script>
        let autoRefreshInterval = null;

        function runCommand(action, outputElementId) {
            const outputEl = document.getElementById(outputElementId || 'statusOutput');
            const buttons = document.querySelectorAll('.btn');

            // Disable all buttons
            buttons.forEach(btn => btn.disabled = true);

            // Show loading
            outputEl.innerHTML = '<span class="spinner"></span> Running command...';

            fetch('admin.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'action=' + action
            })
            .then(r => r.json())
            .then(data => {
                if (action === 'check_files') {
                    let html = '<strong>Directory: ' + data.dir + '</strong>\n\n';
                    for (let file in data.files) {
                        const exists = data.files[file];
                        html += '<div class="file-check ' + (exists ? 'file-exists' : 'file-missing') + '">';
                        html += (exists ? '✅ ' : '❌ ') + file;
                        html += '</div>';
                    }
                    document.getElementById('fileCheckOutput').innerHTML = html;
                } else {
                    outputEl.textContent = data.output || 'No output';
                    if (!data.success) {
                        outputEl.style.color = '#e94560';
                    } else {
                        outputEl.style.color = '#28a745';
                    }
                }
            })
            .catch(err => {
                outputEl.textContent = 'Error: ' + err.message;
                outputEl.style.color = '#e94560';
            })
            .finally(() => {
                // Re-enable buttons
                buttons.forEach(btn => btn.disabled = false);
            });
        }

        function checkFiles() {
            runCommand('check_files', 'fileCheckOutput');
        }

        function refreshLogs() {
            if (autoRefreshInterval) {
                clearInterval(autoRefreshInterval);
                autoRefreshInterval = null;
                document.getElementById('autoRefreshBtn').textContent = '🔄 Auto-refresh OFF';
                document.getElementById('autoRefreshBtn').style.background = '#0f3460';
            } else {
                runCommand('pm2_logs');
                autoRefreshInterval = setInterval(() => {
                    runCommand('pm2_logs');
                }, 5000);
                document.getElementById('autoRefreshBtn').textContent = '⏸️ Auto-refresh ON';
                document.getElementById('autoRefreshBtn').style.background = '#28a745';
            }
        }

        // Auto-check files on load
        window.onload = function() {
            checkFiles();
        };
    </script>
</body>
</html>
