import math
import hashlib
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

delta_time=[0, 10, 20, 30, 40, 50, 60, 70, 80]

deltas = [0, 0.1, 0.3, -0.2, 0.1, 0.0, 0.1, -0.1, 0]

def position(t):
	dt = 0.0000000001
	u = 1
	x = 0
	y =  0
	psi = 0
	delta = 0
	
	for i in np.arange(0,t,dt):
		psi += u*dt*np.tan(delta)/2.8
		x += u*dt*np.cos(psi)
		y += u*dt*np.sin(psi)
		if i in delta_time:
			delta=deltas[delta_time.index(i)]
	return x,y,psi

def get_key(x_y_psi):
	sol = ""
	for value in x_y_psi: 
		sol += "{:.2f}".format(abs(value))
	key = hashlib.sha256(sol.encode()).digest()
	return key
	
def decrypt_flag(key):
	iv = b'\x00'*16
	cipher = AES.new(key, AES.MODE_CBC, iv)
	enc_msg = open('msg.enc', 'rb').read()
	msg_dec = cipher.decrypt(enc_msg)
	print(msg_dec)
	return msg_dec

if __name__ == "__main__":
	t = 13579997531
	x_y_psi = position(t)
	key = get_key(x_y_psi)
	decrypt_flag(key)

