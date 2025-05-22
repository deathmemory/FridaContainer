import time

import frida
import sys

# 修改目标应用的包名为实际的应用包名
TARGET_APP = "com.package.name"  # 替换为实际的应用包名
SCRIPT_PATH = "../../_fcagent.js"


def on_spawn_added(spawn):
    name = spawn.identifier
    print(f"[+] Spawn detected: {name} (PID {spawn.pid})")

    # 仅处理目标 app 及其子进程
    if name == TARGET_APP or name.startswith(f"{TARGET_APP}:"):
        try:
            print(f"[*] Attaching to {name}...")
            session = device.attach(spawn.pid)

            # 读取并注入脚本
            with open(SCRIPT_PATH, "r", encoding="utf-8") as f:
                script = session.create_script(f.read(), runtime="v8")
                script.on("message", on_message)
                script.enable_debugger(port=9229)
                script.load()

            print(f"[+] Script injected into {name}")
            device.resume(spawn.pid)
            print(f"[*] Resumed {name}")
        except Exception as e:
            print(f"[!] Error injecting into {name}: {e}")
    else:
        print(f"[-] Ignoring unrelated spawn: {name}")
        device.resume(spawn.pid)  # 不挂起无关进程


def on_message(message, data):
    print(f"[script message] {message}")


# 初始化
device = frida.get_usb_device()
device.on("spawn-added", on_spawn_added)
time.sleep(1)

# 启动目标应用
pid = device.spawn(TARGET_APP)
print(f"[*] Spawned {TARGET_APP} with PID {pid}")

device.enable_spawn_gating()
print("[*] Spawn gating enabled. Waiting for target app...")

# 恢复目标应用的执行
device.resume(pid)
print(f"[*] Resumed {TARGET_APP}")

# 保持运行
try:
    sys.stdin.read()
except KeyboardInterrupt:
    print("\n[!] Stopping...")
    device.disable_spawn_gating()