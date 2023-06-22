import math
import hashlib
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

FLAG = "CCSC{m4th3m4t1c5_c4n_b3_w31rd_y3t_1nt3r3st1ng!}"

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

def optimal_position(t):
	dt = 1
	u = 1
	x = 0
	y =  0
	psi = 0
	delta = 0
	
	temp_delta_changes = []
	for dc in delta_time:
		if t > dc:
			temp_delta_changes.append(dc)
	deltas.insert(0,deltas[0])
	temp_delta_changes.append(t)
	
	prev_t = 0
	for t in temp_delta_changes:
		delta=deltas[temp_delta_changes.index(t)]
		dt = t - prev_t
		A = math.tan(delta)/2.8
		if A ==0:
			new_psi = psi
			new_x = x + u*dt*np.cos(psi)
			new_y = y +	u*dt*np.sin(psi)
		else:
			new_psi = psi + u*dt*A 
			new_x = x - (np.sin(psi) - np.sin(new_psi))/A
			new_y = y +	(np.cos(psi) - np.cos(new_psi))/A
		prev_t = t
		x,y,psi = new_x, new_y, new_psi
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
	
def encrypt_flag(key):
	iv = b'\x00'*16
	cipher = AES.new(key, AES.MODE_CBC, iv)
	msg_enc = cipher.encrypt(pad(FLAG.encode("ascii"), AES.block_size))
	f = open('msg.enc', 'wb')
	f.write(msg_enc)

if __name__ == "__main__":
	t = 13579997531
	#x_y_psi = position(t)
	x_y_psi = optimal_position(t)
	key = get_key(x_y_psi)
	#encrypt_flag(key)
	decrypt_flag(key)

