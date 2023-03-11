import pyautogui
import keyboard
import time

with open("iptables.txt", "r") as f:
	tables = f.readlines()
keyboard.wait("\n")
for line in tables:
	line.replace("\n", "")
	print(line)
	pyautogui.write(line, 0.01)
pyautogui.write("\n")
