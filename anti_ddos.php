<?php
/**
 * Anti-DDoS Protection Script
 * Blocks malicious bots and protects against DDoS attacks
 */

class AntiDDoS {
    private $max_requests = 60;      // Max requests per minute
    private $block_time = 300;       // Block duration in seconds (5 minutes)
    private $whitelist_ips = [];     // IP whitelist
    private $blacklist_ips = [];     // IP blacklist
    private $log_file = 'ddos_log.txt';
    
    public function __construct() {
        $this->whitelist_ips = $this->getWhitelist();
        $this->blacklist_ips = $this->getBlacklist();
        $this->checkProtection();
    }
    
    private function getClientIP() {
        $ipaddress = '';
        if (isset($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            $ipaddress = $_SERVER['HTTP_CF_CONNECTING_IP'];
        } elseif (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ipaddress = $_SERVER['HTTP_X_FORWARDED_FOR'];
        } elseif (isset($_SERVER['HTTP_X_REAL_IP'])) {
            $ipaddress = $_SERVER['HTTP_X_REAL_IP'];
        } elseif (isset($_SERVER['REMOTE_ADDR'])) {
            $ipaddress = $_SERVER['REMOTE_ADDR'];
        }
        return $ipaddress;
    }
    
    private function getWhitelist() {
        $whitelist = [];
        if (file_exists('whitelist.txt')) {
            $whitelist = file('whitelist.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        }
        // Add localhost and common safe IPs
        $whitelist[] = '127.0.0.1';
        $whitelist[] = '::1';
        return $whitelist;
    }
    
    private function getBlacklist() {
        $blacklist = [];
        if (file_exists('blacklist.txt')) {
            $blacklist = file('blacklist.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        }
        return $blacklist;
    }
    
    private function isBot() {
        $user_agent = strtolower($_SERVER['HTTP_USER_AGENT'] ?? '');
        $bot_patterns = [
            'bot', 'crawler', 'spider', 'scraper', 'curl', 'wget',
            'python', 'perl', 'ruby', 'java', 'php', 'asp.net',
            'libwww', 'http-client', 'masscan', 'nmap', 'sqlmap',
            'nikto', 'burp', 'zmeu', 'ahrefs', 'semrush', 'majestic'
        ];
        
        foreach ($bot_patterns as $pattern) {
            if (strpos($user_agent, $pattern) !== false) {
                return true;
            }
        }
        
        // Check for missing user agent
        if (empty($user_agent)) {
            return true;
        }
        
        return false;
    }
    
    private function isMaliciousRequest() {
        $malicious_patterns = [
            '/\.\./', 'union select', 'select.*from', 'insert into',
            'delete from', 'drop table', 'update.*set', 'exec(',
            'system(', 'passthru(', 'shell_exec(', 'eval(',
            'base64_decode', 'gzinflate', 'str_rot13', '<script',
            'javascript:', 'onload=', 'onerror=', 'alert(',
            'document.cookie', '<?php', '?>', '../', '..\\'
        ];
        
        $request_uri = strtolower($_SERVER['REQUEST_URI']);
        $query_string = strtolower($_SERVER['QUERY_STRING'] ?? '');
        $post_data = strtolower(print_r($_POST, true));
        
        foreach ($malicious_patterns as $pattern) {
            if (strpos($request_uri, $pattern) !== false ||
                strpos($query_string, $pattern) !== false ||
                strpos($post_data, $pattern) !== false) {
                return true;
            }
        }
        
        return false;
    }
    
    private function checkRateLimit() {
        $ip = $this->getClientIP();
        $session_file = 'sessions/' . md5($ip) . '.txt';
        
        if (!file_exists('sessions')) {
            mkdir('sessions', 0755, true);
        }
        
        $current_time = time();
        $requests = [];
        
        if (file_exists($session_file)) {
            $data = file_get_contents($session_file);
            $requests = explode(',', $data);
            $requests = array_filter($requests, function($timestamp) use ($current_time) {
                return ($current_time - $timestamp) < 60;
            });
        }
        
        $requests[] = $current_time;
        
        if (count($requests) > $this->max_requests) {
            // Rate limit exceeded - block the IP
            $this->blockIP($ip);
            return false;
        }
        
        file_put_contents($session_file, implode(',', $requests));
        return true;
    }
    
    private function blockIP($ip) {
        $block_file = 'blocked_ips/' . md5($ip) . '.txt';
        
        if (!file_exists('blocked_ips')) {
            mkdir('blocked_ips', 0755, true);
        }
        
        if (!file_exists($block_file)) {
            file_put_contents($block_file, time());
            $this->logEvent("Blocked IP: $ip - Rate limit exceeded");
        }
    }
    
    private function isIPBlocked() {
        $ip = $this->getClientIP();
        $block_file = 'blocked_ips/' . md5($ip) . '.txt';
        
        if (in_array($ip, $this->whitelist_ips)) {
            return false;
        }
        
        if (in_array($ip, $this->blacklist_ips)) {
            return true;
        }
        
        if (file_exists($block_file)) {
            $block_time = (int)file_get_contents($block_file);
            if ((time() - $block_time) < $this->block_time) {
                return true;
            } else {
                unlink($block_file);
            }
        }
        
        return false;
    }
    
    private function logEvent($message) {
        $log_entry = date('Y-m-d H:i:s') . " - " . $message . " - IP: " . $this->getClientIP() . "\n";
        file_put_contents($this->log_file, $log_entry, FILE_APPEND);
    }
    
    private function sendBlockResponse() {
        header('HTTP/1.0 403 Forbidden');
        header('Status: 403 Forbidden');
        echo '<!DOCTYPE html>
        <html>
        <head>
            <title>Access Denied</title>
            <style>
                body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #f5f5f5; }
                .container { background: white; padding: 30px; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); max-width: 500px; margin: 0 auto; }
                h1 { color: #d32f2f; }
                p { color: #666; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Access Denied</h1>
                <p>Your IP has been blocked due to suspicious activity.</p>
                <p>Please try again later.</p>
                <p><small>Reference: ' . md5($this->getClientIP()) . '</small></p>
            </div>
        </body>
        </html>';
        exit;
    }
    
    public function checkProtection() {
        // Check if IP is blocked
        if ($this->isIPBlocked()) {
            $this->logEvent("Blocked request from IP");
            $this->sendBlockResponse();
        }
        
        // Check for malicious requests
        if ($this->isMaliciousRequest()) {
            $this->blockIP($this->getClientIP());
            $this->logEvent("Malicious request detected and blocked");
            $this->sendBlockResponse();
        }
        
        // Check for bots (optional - uncomment if needed)
        // if ($this->isBot()) {
        //     $this->logEvent("Bot detected and blocked");
        //     $this->sendBlockResponse();
        // }
        
        // Check rate limit
        if (!$this->checkRateLimit()) {
            $this->sendBlockResponse();
        }
    }
}

// Initialize Anti-DDoS protection
$anti_ddos = new AntiDDoS();

// Your website code continues here
// For example:
// include 'index.php';
?>