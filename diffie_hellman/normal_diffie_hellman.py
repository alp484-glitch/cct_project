"""
Normal Diffie-Hellman Key Exchange
This script demonstrates a secure key exchange between Alice and Bob
when no attacker is present.
"""

import random

def print_header(text):
    """Print a formatted header"""
    print("\n" + "="*60)
    print(f"  {text}")
    print("="*60)

def print_step(step_num, text):
    """Print a formatted step"""
    print(f"\n[Step {step_num}] {text}")

# Public parameters (known to everyone)
print_header("DIFFIE-HELLMAN KEY EXCHANGE (NO ATTACK)")

print("\n🔓 PUBLIC PARAMETERS (Known to everyone)")
p = 23  # A prime number (in practice, this would be much larger)
g = 5   # A primitive root modulo p
print(f"   p (prime modulus) = {p}")
print(f"   g (generator/base) = {g}")

# Alice's side
print_step(1, "Alice generates her private key")
alice_private = random.randint(1, p-1)
print(f"   Alice's private key (a) = {alice_private}")
print(f"   ⚠️  This is SECRET and never transmitted!")

print_step(2, "Alice computes her public key")
alice_public = pow(g, alice_private, p)  # g^a mod p
print(f"   Alice's public key (A) = g^a mod p = {g}^{alice_private} mod {p} = {alice_public}")
print(f"   ✉️  Alice sends A = {alice_public} to Bob")

# Bob's side
print_step(3, "Bob generates his private key")
bob_private = random.randint(1, p-1)
print(f"   Bob's private key (b) = {bob_private}")
print(f"   ⚠️  This is SECRET and never transmitted!")

print_step(4, "Bob computes his public key")
bob_public = pow(g, bob_private, p)  # g^b mod p
print(f"   Bob's public key (B) = g^b mod p = {g}^{bob_private} mod {p} = {bob_public}")
print(f"   ✉️  Bob sends B = {bob_public} to Alice")

# Shared secret computation
print_step(5, "Alice computes the shared secret")
alice_shared_secret = pow(bob_public, alice_private, p)  # B^a mod p
print(f"   Shared secret = B^a mod p = {bob_public}^{alice_private} mod {p} = {alice_shared_secret}")

print_step(6, "Bob computes the shared secret")
bob_shared_secret = pow(alice_public, bob_private, p)  # A^b mod p
print(f"   Shared secret = A^b mod p = {alice_public}^{bob_private} mod {p} = {bob_shared_secret}")

# Verification
print_header("RESULT")
print(f"\n✅ Alice's shared secret: {alice_shared_secret}")
print(f"✅ Bob's shared secret:   {bob_shared_secret}")

if alice_shared_secret == bob_shared_secret:
    print(f"\n🎉 SUCCESS! Both parties have the same shared secret: {alice_shared_secret}")
    print("   This secret can now be used as an encryption key.")
else:
    print("\n❌ ERROR: Shared secrets do not match!")

print("\n" + "="*60)
print("  Key Exchange Complete - No Attacker Present")
print("="*60 + "\n")
