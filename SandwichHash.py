import struct, time, secrets, hashlib, argon2

def hashModifiedPBKDF2(credential: bytes, salt: bytes, n: int) -> bytes:
	r = credential
	for i in range (n):
		r = hashlib.sha256(r+salt).digest()
	return r

def hashArgon2(credential: bytes, salt: bytes) -> bytes:
	return argon2.low_level.hash_secret_raw(credential, salt, time_cost=1, memory_cost=8, parallelism=1, hash_len=64, type=argon2.low_level.Type.D)

class SandwichHashEnrollment:
	def __init__(self, Hp: list[bytes], salt: list[bytes], Hc: bytes, argonSalt: bytes):
		self.Hp: list[bytes] = Hp
		self.salt: list[bytes] = salt
		self.Hc: bytes = Hc
		self.argonSalt: bytes = argonSalt

class SandwichHashTransfer:
	def __init__(self, Ht: bytes, Hq: list[bytes], Bt: bytes):
		self.Ht: bytes = Ht
		self.Hq: list[bytes] = Hq
		self.Bt: bytes = Bt
		self.timestamp: float = struct.unpack('<f', Bt)[0]

class SandwichHashServer:
	def __init__(self, R: int, nR: int, lb: int, saltLength: int, timeTolerance: float):
		self.R: int = R
		self.nR: int = nR
		self.lb: int = lb
		self.saltLength: int = saltLength
		self.timeTolerance: float = timeTolerance
	
	def enroll(self, credential: str) -> SandwichHashEnrollment:
		argonSalt: bytes = secrets.token_bytes(self.saltLength)
		Hb: bytes = hashArgon2(credential.encode(), argonSalt)
		saltList: list[bytes] = []
		Hp: list[bytes] = []
		for i in range(self.R):
			salt: bytes = secrets.token_bytes(self.saltLength)
			saltList.append(salt)
			Hp.append(hashModifiedPBKDF2(Hb, salt, self.nR))
		Hc: bytes = hashArgon2(b''.join(Hp), argonSalt)
		return SandwichHashEnrollment([i[:self.lb] for i in Hp], saltList, Hc, argonSalt)

	def approve(self, transfer: SandwichHashTransfer, enrollment: SandwichHashEnrollment) -> bool:
		now: float = time.time()
		delta: float = now - transfer.timestamp
		if delta > self.timeTolerance: return False
		randomized: list[bytes] = []
		HpList: list[bytes] = []
		for i in range(self.R):
			nq, Hp = self.findRound(transfer.Hq[i], enrollment.salt[i], enrollment.Hp[i])
			if nq < 0: return False
			nq = self.nR - nq
			randomized.append(struct.pack('<i', nq))
			HpList.append(Hp)
		Ht: bytes = hashArgon2(b''.join(transferred.Hq)+b''.join(randomized)+transferred.Bt, enrollment.argonSalt)
		if Ht != transferred.Ht: return False
		Hc: bytes = hashArgon2(b''.join(HpList), enrollment.argonSalt)
		if Hc != enrollment.Hc: return False
		return True
	
	def findRound(self, Hq: bytes, salt: bytes, Hp: bytes) -> tuple[int, bytes]:
		lb = len(Hp)
		r: bytes = Hq
		for i in range(self.nR):
			r = hashlib.sha256(r+salt).digest()
			if r[:lb] == Hp: return i+1, r
		return -1, None

class SandwichHashClient:
	def __init__(self, R: int, nR: int, minNq: int):
		self.R: int = R
		self.nR: int = nR
		self.minNq: int = minNq
	
	def hash(self, credential: str, saltList: list[bytes], argonSalt: bytes) -> SandwichHashTransfer:
		Hb: bytes = hashArgon2(credential.encode(), argonSalt)
		HqList: list[bytes] = []
		now: float = time.time()
		Bt: bytes = struct.pack('<f', now)
		randomized: list[bytes] = []
		interval: int = self.nR - self.minNq
		for i, salt in enumerate(saltList):
			nq = (struct.unpack('<i', secrets.token_bytes(4))[0]%interval) + self.minNq
			randomized.append(struct.pack('<i', nq))
			Hq: bytes = hashModifiedPBKDF2(Hb, salt, nq)
			HqList.append(Hq)
		Ht: bytes = hashArgon2(b''.join(HqList)+b''.join(randomized)+Bt, argonSalt)
		return SandwichHashTransfer(Ht, HqList, Bt)

class SandwichHash:
	def __init__(self, R: int, nR: int, lb: int, saltLength: int, timeTolerance: float, minNq: int):
		self.R: int = R
		self.nR: int = nR
		self.lb: int = lb
		self.saltLength: int = saltLength
		self.timeTolerance: float = timeTolerance
		self.minNq = minNq
		self.server: SandwichHashServer = SandwichHashServer(R, nR, lb, saltLength, timeTolerance)
		self.client: SandwichHashClient = SandwichHashClient(R, nR, minNq)
	
	def enroll(self, credential: str) -> SandwichHashEnrollment:
		return self.server.enroll(credential)

	def hash(self, credential: str, salt: list[bytes], argonSalt: bytes) -> SandwichHashTransfer:
		return self.client.hash(credential, salt, argonSalt)

	def approve(self, transfer: SandwichHashTransfer, enrollment: SandwichHashEnrollment) -> bool:
		return self.server.approve(transfer, enrollment)

if __name__ == '__main__':
	password = 'DeDoDoDoDeDaDaDa'
	hasher = SandwichHash(R=32, nR=2**15, lb=8, saltLength=32, timeTolerance=60.0, minNq=512)
	enrolled = hasher.enroll(password)
	transferred = hasher.hash(password, enrolled.salt, enrolled.argonSalt)
	result = hasher.approve(transferred, enrolled)
	print(result)
	# Note Modify some hash to make it wrong.
	transferred.Hq[0] = secrets.token_bytes(32)
	result = hasher.approve(transferred, enrolled)
	print(result)
