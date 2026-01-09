 
#!/usr/bin/env python3
"""
高可靠连续录像系统 - 录制模块
专为ARM设备优化，支持断网续传和异常推送
"""

import subprocess
import time
import os
import signal
import sys
import threading
import smtplib
import ssl
import requests
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header
from email.utils import formatdate
from config import *

def log(message, level="INFO"):
    """带等级的日志函数"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_msg = f"[{timestamp}] [{level}] {message}"
    print(log_msg)
    
    # 写入系统日志
    with open("/var/tmp/video_recorder.log", "a") as f:
        f.write(log_msg + "\n")

class PushplusNotifier:
    """Pushplus推送通知器（黑色主题）"""
    
    def __init__(self):
        self.enabled = ENABLE_PUSHPLUS
        self.token = PUSHPLUS_TOKEN
        self.sent_alerts = {}  # 已发送提醒的时间戳 {alert_type: last_sent_time}
        self.min_interval = 600  # 最小推送间隔（秒）
        
    def send_alert(self, title, message, alert_type="recorder_error"):
        """发送Pushplus推送（黑色主题）"""
        
        # 检查是否启用Pushplus
        if not self.enabled:
            return False
        
        # 检查token是否配置
        if not self.token:
            return False
        
        # 检查是否在最小间隔内（避免频繁发送）
        current_time = time.time()
        last_sent = self.sent_alerts.get(alert_type, 0)
        if current_time - last_sent < self.min_interval:
            log(f"Pushplus推送间隔内，跳过发送: {alert_type}", "INFO")
            return False
            
        try:
            # 构建黑色主题的推送内容
            content = f"""
<div style="background-color: #1a1a1a; color: #ffffff; padding: 20px; border-radius: 10px; font-family: 'Microsoft YaHei', sans-serif;">
<div style="text-align: center; margin-bottom: 20px;">
<h2 style="color: #ff6b6b; margin: 0;">🚨 {title}</h2>
</div>

<div style="background-color: #2d2d2d; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
<h3 style="color: #4ecdc4; margin-top: 0; border-bottom: 2px solid #4ecdc4; padding-bottom: 5px;">📹 录制模块报警</h3>
<p style="color: #cccccc; line-height: 1.6; margin: 10px 0;">{message}</p>
</div>

<div style="background-color: #2d2d2d; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
<h3 style="color: #4ecdc4; margin-top: 0; border-bottom: 2px solid #4ecdc4; padding-bottom: 5px;">📊 系统信息</h3>
<ul style="color: #cccccc; padding-left: 20px;">
<li><strong>RTSP源：</strong>{RTSP_URL.split('@')[1].split(':')[0] if '@' in RTSP_URL else RTSP_URL}</li>
<li><strong>本地缓冲：</strong>{LOCAL_BUFFER_DIR}</li>
<li><strong>分段时长：</strong>{SEGMENT_DURATION}秒</li>
<li><strong>当前时间：</strong>{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</li>
</ul>
</div>

<div style="background-color: #2d2d2d; padding: 15px; border-radius: 8px;">
<h3 style="color: #4ecdc4; margin-top: 0; border-bottom: 2px solid #4ecdc4; padding-bottom: 5px;">📋 最近日志</h3>
<pre style="background-color: #000000; color: #00ff00; padding: 10px; border-radius: 5px; font-size: 12px; overflow: auto; max-height: 200px;">
{self._get_recent_logs()}
</pre>
</div>

<div style="margin-top: 20px; text-align: center; color: #888888; font-size: 12px;">
⏰ 报警时间：{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
</div>
</div>
"""
            
            # 准备推送参数
            params = {
                "token": self.token,
                "title": f"录制模块报警：{title}",
                "content": content,
                "template": "html",
            }
            
            # 添加可选参数
            if PUSHPLUS_TOPIC:
                params["topic"] = PUSHPLUS_TOPIC
            
            # 发送推送请求
            response = requests.post(
                "http://www.pushplus.plus/send",
                json=params,
                timeout=30
            )
            
            result = response.json()
            
            if result.get("code") == 200:
                # 更新发送记录
                self.sent_alerts[alert_type] = current_time
                log(f"✅ Pushplus推送发送成功: {title}", "ALERT")
                return True
            else:
                log(f"Pushplus推送失败: {result.get('msg', '未知错误')}", "ERROR")
                return False
                
        except requests.exceptions.RequestException as e:
            log(f"Pushplus网络请求失败: {e}", "ERROR")
            return False
        except Exception as e:
            log(f"Pushplus推送失败: {e}", "ERROR")
            return False
    
    def _get_recent_logs(self):
        """获取最近的系统日志"""
        try:
            log_file = "/var/tmp/video_recorder.log"
            if os.path.exists(log_file):
                with open(log_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    # 获取最后 PUSHPLUS_LOG_LINES 行
                    recent_lines = lines[-PUSHPLUS_LOG_LINES:] if len(lines) > PUSHPLUS_LOG_LINES else lines
                    return "".join(recent_lines).strip()
            return "暂无系统日志"
        except Exception as e:
            log(f"获取系统日志失败: {e}", "ERROR")
            return f"获取系统日志失败: {str(e)}"

class EmailNotifier:
    """邮件通知器 - 专为189邮箱优化（黑色主题样式）"""
    
    def __init__(self):
        self.enabled = ENABLE_EMAIL_ALERT
        self.sent_alerts = {}  # 已发送提醒的时间戳 {alert_type: last_sent_time}
        self.min_interval = 600  # 最小推送间隔（秒）
        
    def send_alert(self, title, message, alert_type="recorder_error"):
        """发送录制异常提醒邮件（黑色主题样式）"""
        
        # 检查是否启用邮件提醒
        if not self.enabled:
            return False
        
        # 检查是否在最小间隔内（避免频繁发送）
        current_time = time.time()
        last_sent = self.sent_alerts.get(alert_type, 0)
        if current_time - last_sent < self.min_interval:
            log(f"邮件提醒间隔内，跳过发送: {alert_type}", "INFO")
            return False
            
        try:
            # 构建黑色主题的邮件内容（使用HTML）
            email_body = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>录制模块报警</title>
    <style>
        body {{
            background-color: #1a1a1a;
            color: #ffffff;
            font-family: 'Microsoft YaHei', sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
        }}
        .container {{
            max-width: 800px;
            margin: 0 auto;
            background-color: #2d2d2d;
            border-radius: 10px;
            padding: 30px;
            box-shadow: 0 0 20px rgba(0,0,0,0.3);
        }}
        .header {{
            text-align: center;
            margin-bottom: 30px;
            border-bottom: 2px solid #ff6b6b;
            padding-bottom: 15px;
        }}
        .header h1 {{
            color: #ff6b6b;
            margin: 0;
        }}
        .section {{
            background-color: #3d3d3d;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            border-left: 4px solid #4ecdc4;
        }}
        .section h2 {{
            color: #4ecdc4;
            margin-top: 0;
            border-bottom: 1px solid #4ecdc4;
            padding-bottom: 10px;
        }}
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 10px;
            margin: 15px 0;
        }}
        .info-item {{
            background-color: #4d4d4d;
            padding: 10px;
            border-radius: 5px;
        }}
        .info-item strong {{
            color: #ffd166;
        }}
        .log-box {{
            background-color: #000000;
            color: #00ff00;
            padding: 15px;
            border-radius: 5px;
            font-family: monospace;
            font-size: 12px;
            max-height: 300px;
            overflow-y: auto;
            white-space: pre-wrap;
        }}
        .footer {{
            text-align: center;
            margin-top: 30px;
            color: #888888;
            font-size: 12px;
            border-top: 1px solid #444;
            padding-top: 15px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚨 {title}</h1>
        </div>
        
        <div class="section">
            <h2>📹 录制模块报警</h2>
            <p style="color: #cccccc;">{message}</p>
        </div>
        
        <div class="section">
            <h2>📊 系统信息</h2>
            <div class="info-grid">
                <div class="info-item">
                    <strong>RTSP源：</strong><br>
                    {RTSP_URL.split('@')[1].split(':')[0] if '@' in RTSP_URL else RTSP_URL}
                </div>
                <div class="info-item">
                    <strong>本地缓冲：</strong><br>
                    {LOCAL_BUFFER_DIR}
                </div>
                <div class="info-item">
                    <strong>分段时长：</strong><br>
                    {SEGMENT_DURATION}秒
                </div>
                <div class="info-item">
                    <strong>当前时间：</strong><br>
                    {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>📋 最近日志</h2>
            <div class="log-box">
{self._get_recent_logs()}
            </div>
        </div>
        
        <div class="footer">
            ⏰ 报警时间：{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}<br>
            📧 邮件发送系统 - 高可靠连续录像系统
        </div>
    </div>
</body>
</html>
"""
            
            # 创建邮件对象
            msg = MIMEMultipart()
            msg['From'] = EMAIL_USERNAME
            msg['To'] = ', '.join(EMAIL_RECEIVERS)
            msg['Subject'] = Header(f"录制模块报警：{title}", 'utf-8')
            msg['Date'] = formatdate(localtime=True)
            
            # 添加HTML内容
            html_part = MIMEText(email_body, 'html', 'utf-8')
            msg.attach(html_part)
            
            # 连接SMTP服务器并发送（189邮箱专用配置）
            if SMTP_SSL:
                context = ssl.create_default_context()
                server = smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context)
            else:
                server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
                server.starttls(context=ssl.create_default_context())
            
            # 登录（使用客户端专用密码）
            server.login(EMAIL_USERNAME, EMAIL_PASSWORD)
            
            # 发送邮件
            server.sendmail(EMAIL_USERNAME, EMAIL_RECEIVERS, msg.as_string())
            server.quit()
            
            # 更新发送记录
            self.sent_alerts[alert_type] = current_time
            log(f"✅ 邮件提醒发送成功: {title}", "ALERT")
            return True
            
        except smtplib.SMTPAuthenticationError as e:
            log(f"邮件认证失败: {e}", "ERROR")
            return False
        except smtplib.SMTPException as e:
            log(f"邮件发送失败(SMTP错误): {e}", "ERROR")
            return False
        except Exception as e:
            log(f"邮件发送失败: {e}", "ERROR")
            return False
    
    def _get_recent_logs(self):
        """获取最近的系统日志"""
        try:
            log_file = "/var/tmp/video_recorder.log"
            if os.path.exists(log_file):
                with open(log_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    # 获取最后 PUSHPLUS_LOG_LINES 行
                    recent_lines = lines[-PUSHPLUS_LOG_LINES:] if len(lines) > PUSHPLUS_LOG_LINES else lines
                    return "".join(recent_lines).strip()
            return "暂无系统日志"
        except Exception as e:
            log(f"获取系统日志失败: {e}", "ERROR")
            return f"获取系统日志失败: {str(e)}"

class AlertManager:
    """警报管理器 - 负责同时发送邮件和Pushplus推送"""
    
    def __init__(self):
        self.email_notifier = EmailNotifier()
        self.pushplus_notifier = PushplusNotifier()
        self.alerts_sent = {}  # 已发送的警报 {alert_type: count}
        
    def send_alert(self, title, message, alert_type="recorder_error"):
        """
        同时发送邮件和Pushplus推送
        返回：是否至少有一种方式发送成功
        """
        results = {
            'email': False,
            'pushplus': False
        }
        
        # 记录警报次数
        self.alerts_sent[alert_type] = self.alerts_sent.get(alert_type, 0) + 1
        
        # 同时发送邮件和Pushplus推送
        threads = []
        
        # 发送邮件（在单独线程中）
        if self.email_notifier.enabled:
            email_thread = threading.Thread(
                target=lambda: self._send_email_thread(title, message, alert_type, results),
                daemon=True
            )
            threads.append(email_thread)
            email_thread.start()
        
        # 发送Pushplus推送（在单独线程中）
        if self.pushplus_notifier.enabled and self.pushplus_notifier.token:
            pushplus_thread = threading.Thread(
                target=lambda: self._send_pushplus_thread(title, message, alert_type, results),
                daemon=True
            )
            threads.append(pushplus_thread)
            pushplus_thread.start()
        
        # 等待所有线程完成（最多10秒）
        for thread in threads:
            thread.join(timeout=10)
        
        # 记录结果
        email_success = results.get('email', False)
        pushplus_success = results.get('pushplus', False)
        
        if email_success:
            log(f"✅ 邮件警报发送成功: {title}", "INFO")
        else:
            log(f"❌ 邮件警报发送失败: {title}", "WARNING")
            
        if pushplus_success:
            log(f"✅ Pushplus警报发送成功: {title}", "INFO")
        else:
            log(f"❌ Pushplus警报发送失败: {title}", "WARNING")
        
        # 返回是否至少有一种方式发送成功
        return email_success or pushplus_success
    
    def _send_email_thread(self, title, message, alert_type, results):
        """发送邮件线程"""
        try:
            results['email'] = self.email_notifier.send_alert(title, message, alert_type)
        except Exception as e:
            log(f"邮件警报线程异常: {e}", "ERROR")
            results['email'] = False
    
    def _send_pushplus_thread(self, title, message, alert_type, results):
        """发送Pushplus推送线程"""
        try:
            results['pushplus'] = self.pushplus_notifier.send_alert(title, message, alert_type)
        except Exception as e:
            log(f"Pushplus警报线程异常: {e}", "ERROR")
            results['pushplus'] = False

class FileRenamer:
    """文件重命名器 - 将.part文件重命名为.mp4"""
    
    def __init__(self, alert_manager):
        self.running = False
        self.thread = None
        self.alert_manager = alert_manager
        
    def start(self):
        """启动重命名线程"""
        self.running = True
        self.thread = threading.Thread(target=self._rename_loop, daemon=True)
        self.thread.start()
        log("文件重命名器已启动")
        
    def stop(self):
        """停止重命名器"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        log("文件重命名器已停止")
    
    def _rename_loop(self):
        """重命名循环"""
        while self.running:
            try:
                self._rename_part_files()
            except Exception as e:
                log(f"重命名文件时发生错误: {e}", "ERROR")
                # 发送重命名错误警报
                self.alert_manager.send_alert(
                    title="文件重命名错误",
                    message=f"重命名文件时发生错误：{str(e)}",
                    alert_type="rename_error"
                )
            
            # 等待下次检查
            time.sleep(RENAME_CHECK_INTERVAL)
    
    def _rename_part_files(self):
        """重命名.part文件为.mp4"""
        if not USE_PART_EXTENSION:
            return
        
        try:
            renamed_count = 0
            
            # 扫描缓冲目录中的.part文件
            for filename in os.listdir(LOCAL_BUFFER_DIR):
                if filename.endswith(PART_EXTENSION):
                    part_path = os.path.join(LOCAL_BUFFER_DIR, filename)
                    mp4_filename = filename.replace(PART_EXTENSION, FINAL_EXTENSION)
                    mp4_path = os.path.join(LOCAL_BUFFER_DIR, mp4_filename)
                    
                    # 检查文件是否稳定（不再被写入）
                    if self._is_file_stable(part_path):
                        try:
                            # 重命名文件
                            os.rename(part_path, mp4_path)
                            renamed_count += 1
                            log(f"重命名文件: {filename} -> {mp4_filename}")
                        except Exception as e:
                            log(f"重命名文件失败 {filename}: {e}", "ERROR")
            
            if renamed_count > 0:
                log(f"成功重命名 {renamed_count} 个文件")
                
        except Exception as e:
            log(f"扫描.part文件时发生错误: {e}", "ERROR")
    
    def _is_file_stable(self, filepath):
        """检查文件是否稳定（不再被写入）"""
        if not os.path.exists(filepath):
            return False
        
        try:
            # 获取文件的最后修改时间
            mtime = os.path.getmtime(filepath)
            current_time = time.time()
            
            # 关键修改：检查文件是否在最近10秒内被修改过
            # 如果10秒内被修改过，说明可能还在写入
            if current_time - mtime < 10:
                return False  # 文件在10秒内被修改过，可能还在写入
            
            # 检查文件大小是否变化
            size1 = os.path.getsize(filepath)
            time.sleep(2)  # 等待2秒
            size2 = os.path.getsize(filepath)
            
            # 如果文件大小没有变化，说明文件已经完成
            return size1 == size2 and size1 > 1024  # 确保文件至少1KB
            
        except Exception:
            return False
    
    def force_rename_all(self):
        """强制重命名所有.part文件（用于启动时清理）"""
        if not USE_PART_EXTENSION:
            return
        
        try:
            renamed_count = 0
            
            for filename in os.listdir(LOCAL_BUFFER_DIR):
                if filename.endswith(PART_EXTENSION):
                    part_path = os.path.join(LOCAL_BUFFER_DIR, filename)
                    mp4_filename = filename.replace(PART_EXTENSION, FINAL_EXTENSION)
                    mp4_path = os.path.join(LOCAL_BUFFER_DIR, mp4_filename)
                    
                    if os.path.exists(part_path):
                        try:
                            os.rename(part_path, mp4_path)
                            renamed_count += 1
                        except Exception as e:
                            log(f"强制重命名失败 {filename}: {e}", "ERROR")
            
            if renamed_count > 0:
                log(f"强制重命名了 {renamed_count} 个残留的.part文件")
                
        except Exception as e:
            log(f"强制重命名时发生错误: {e}", "ERROR")

class VideoRecorder:
    """视频录制器类"""
    
    def __init__(self):
        self.process = None
        self.running = False
        self.alert_manager = AlertManager()
        self.renamer = FileRenamer(self.alert_manager)
        self.restart_count = 0  # 重启次数统计
        self.last_restart_time = 0  # 上次重启时间
        
    def start(self):
        """启动FFmpeg录制到本地缓冲区"""
        if USE_PART_EXTENSION:
            # 使用.part扩展名
            output_pattern = os.path.join(LOCAL_BUFFER_DIR, f"%Y%m%d%H%M%S{PART_EXTENSION}")
        else:
            # 直接使用.mp4扩展名
            output_pattern = os.path.join(LOCAL_BUFFER_DIR, "%Y%m%d%H%M%S.mp4")
        
        cmd = [
            'ffmpeg',
            '-y',
            '-rtsp_transport', 'tcp',
            '-fflags', 'nobuffer',
            '-i', RTSP_URL,
            '-c:v', 'copy',
            '-c:a', 'aac', '-b:a', '64k', '-ac', '1', '-ar', '16000',
            '-f', 'segment',
            '-segment_time', str(SEGMENT_DURATION),
            '-segment_format', 'mp4',
            '-reset_timestamps', '1',
            '-strftime', '1',
            '-segment_atclocktime', '1',
            output_pattern
        ]
        
        log(f"FFmpeg命令: {' '.join(cmd)}")
        
        try:
            # 启动重命名器
            #self.renamer.start()
            
            # 强制重命名之前残留的.part文件
            #self.renamer.force_rename_all()
            
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                start_new_session=True
            )
            
            self.running = True
            self.restart_count += 1
            self.last_restart_time = time.time()
            
            log(f"录制进程已启动，PID: {self.process.pid}")
            log(f"本地缓冲目录: {LOCAL_BUFFER_DIR}")
            log(f"输出模式: {output_pattern}")
            
            # 发送启动成功通知
            if self.restart_count == 1:
                self.alert_manager.send_alert(
                    title="录制模块启动成功",
                    message=f"录制模块已成功启动\nRTSP源：{RTSP_URL.split('@')[1].split(':')[0] if '@' in RTSP_URL else RTSP_URL}\n本地缓冲：{LOCAL_BUFFER_DIR}",
                    alert_type="recorder_started"
                )
            
            return True
            
        except Exception as e:
            log(f"启动录制失败: {e}", "ERROR")
            # 发送启动失败警报
            self.alert_manager.send_alert(
                title="录制模块启动失败",
                message=f"录制模块启动失败：{str(e)}",
                alert_type="recorder_start_failed"
            )
            return False
    
    def stop(self):
        """停止录制"""
        # 停止重命名器
        self.renamer.stop()
        
        # 停止录制进程
        if self.process and self.process.poll() is None:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
                log("录制进程已正常停止")
                
                # 发送停止通知
                self.alert_manager.send_alert(
                    title="录制模块已停止",
                    message="录制模块已正常停止",
                    alert_type="recorder_stopped"
                )
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
                log("录制进程被强制终止")
                
                # 发送强制停止警报
                self.alert_manager.send_alert(
                    title="录制模块强制停止",
                    message="录制进程无响应，已被强制终止",
                    alert_type="recorder_killed"
                )
            except Exception as e:
                log(f"停止录制进程失败: {e}", "ERROR")
            
            self.running = False
    
    def is_running(self):
        """检查录制是否在运行"""
        if self.process:
            return self.process.poll() is None
        return False
    
    def restart_if_needed(self):
        """如果需要则重启录制进程"""
        if not self.is_running():
            current_time = time.time()
            
            # 检查是否频繁重启（5分钟内重启3次）
            if (current_time - self.last_restart_time < 300 and 
                self.restart_count % 3 == 0 and self.restart_count > 0):
                
                # 发送频繁重启警报
                self.alert_manager.send_alert(
                    title="录制模块频繁重启",
                    message=f"录制模块在5分钟内已重启{self.restart_count}次\nRTSP源可能存在问题或网络连接不稳定",
                    alert_type="recorder_frequent_restart"
                )
            
            log("录制进程意外退出，尝试重启...", "WARNING")
            
            # 发送重启警报
            self.alert_manager.send_alert(
                title="录制模块重启",
                message=f"录制进程意外退出，正在尝试第{self.restart_count + 1}次重启",
                alert_type="recorder_restarting"
            )
            
            return self.start()
        return True

def main():
    """录制模块主函数"""
    print("\n" + "="*60)
    print("高可靠连续录像系统 - 录制模块")
    print(f"RTSP源: {RTSP_URL}")
    print(f"本地缓冲: {LOCAL_BUFFER_DIR}")
    if USE_PART_EXTENSION:
        print(f"使用临时扩展名: {PART_EXTENSION} -> {FINAL_EXTENSION}")
    if ENABLE_EMAIL_ALERT:
        print(f"邮件提醒: 已启用 ({EMAIL_USERNAME})")
    else:
        print("邮件提醒: 未启用")
    if ENABLE_PUSHPLUS:
        print(f"Pushplus推送: 已启用")
    else:
        print("Pushplus推送: 未启用")
    print("警报模式: 邮件和Pushplus同时推送")
    print("主题风格: 黑色主题")
    print("="*60)
    
    # 初始化目录
    init_directories()
    
    # 创建录制器实例
    recorder = VideoRecorder()
    
    # 注册信号处理
    def signal_handler(signum, frame):
        log(f"收到信号 {signum}，准备退出...")
        recorder.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # 启动录制
    if not recorder.start():
        log("录制启动失败，程序退出", "ERROR")
        sys.exit(1)
    
    log("录制模块启动完成，开始录制")
    log("按 Ctrl+C 停止程序")
    
    # 主监控循环
    error_count = 0
    max_errors = 10
    
    try:
        while True:
            # 监控录制进程，必要时重启
            if not recorder.is_running():
                log("录制进程已停止，尝试重启...", "WARNING")
                if not recorder.restart_if_needed():
                    error_count += 1
                    if error_count >= max_errors:
                        # 发送致命错误警报
                        recorder.alert_manager.send_alert(
                            title="录制模块严重故障",
                            message=f"录制模块连续重启失败{error_count}次，系统可能存在严重问题",
                            alert_type="recorder_critical_error"
                        )
                        log(f"录制模块连续失败{error_count}次，程序退出", "ERROR")
                        break
                    log(f"重启失败，等待60秒后重试 (失败{error_count}/{max_errors})", "ERROR")
                    time.sleep(60)
                    continue
                else:
                    error_count = 0  # 重置错误计数
            
            # 检查缓冲目录状态
            try:
                files = os.listdir(LOCAL_BUFFER_DIR)
                part_files = [f for f in files if f.endswith(PART_EXTENSION)]
                mp4_files = [f for f in files if f.endswith(FINAL_EXTENSION)]
                
                # 定期报告文件状态
                if len(part_files) > 10 or len(mp4_files) > 10:
                    log(f"缓冲文件状态: {len(part_files)}个.part文件, {len(mp4_files)}个.mp4文件")
            except Exception as e:
                log(f"检查缓冲目录失败: {e}", "ERROR")
            
            # 简单心跳
            time.sleep(30)
            
    except KeyboardInterrupt:
        log("收到停止信号", "INFO")
    except Exception as e:
        log(f"录制模块主循环异常: {e}", "ERROR")
        # 发送主循环异常警报
        recorder.alert_manager.send_alert(
            title="录制模块主循环异常",
            message=f"录制模块主循环发生异常：{str(e)}",
            alert_type="recorder_main_loop_error"
        )
    finally:
        recorder.stop()
        log("录制模块已停止", "INFO")

if __name__ == "__main__":
    main()