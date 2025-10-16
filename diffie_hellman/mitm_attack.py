"""
Man-in-the-Middle Attack on Diffie-Hellman Key Exchange
This script demonstrates how an attacker can intercept and manipulate
the key exchange when there is no authentication.
"""

import random

def print_header(text):
    """Print a formatted header"""
    print("\n" + "="*70)
    print(f"  {text}")
    print("="*70)

def print_step(step_num, text):
    """Print a formatted step"""
    print(f"\n[Step {step_num}] {text}")

def print_attack_warning(text):
    """Print an attack action"""
    print(f"   🚨 ATTACK: {text}")

# Public parameters (known to everyone)
print_header("DIFFIE-HELLMAN WITH MAN-IN-THE-MIDDLE ATTACK")

print("\n🔓 PUBLIC PARAMETERS (Known to everyone, including Mallory)")
p = 23  # A prime number
g = 5   # A primitive root modulo p
print(f"   p (prime modulus) = {p}")
print(f"   g (generator/base) = {g}")

# Alice's side
print_step(1, "Alice generates her private key")
alice_private = random.randint(1, p-1)
print(f"   Alice's private key (a) = {alice_private}")

print_step(2, "Alice computes and sends her public key")
alice_public = pow(g, alice_private, p)
print(f"   Alice's public key (A) = {g}^{alice_private} mod {p} = {alice_public}")
print(f"   ✉️  Alice sends A = {alice_public} → [intended for Bob]")

# Mallory intercepts
print_step(3, "🚨 MALLORY INTERCEPTS Alice's message")
print_attack_warning(f"Mallory intercepts A = {alice_public}")
print_attack_warning("Mallory BLOCKS this from reaching Bob!")
print(f"   Mallory generates her own private key for Alice")
mallory_private_for_alice = random.randint(1, p-1)
print(f"   Mallory's private key (m₁) = {mallory_private_for_alice}")
mallory_public_for_bob = pow(g, mallory_private_for_alice, p)
print(f"   Mallory's public key (M₁) = {g}^{mallory_private_for_alice} mod {p} = {mallory_public_for_bob}")
print(f"   ✉️  Mallory sends M₁ = {mallory_public_for_bob} → Bob (pretending to be Alice)")

# Bob's side
print_step(4, "Bob generates his private key")
bob_private = random.randint(1, p-1)
print(f"   Bob's private key (b) = {bob_private}")
print(f"   ⚠️  Bob thinks he received Alice's public key, but it's actually Mallory's!")

print_step(5, "Bob computes and sends his public key")
bob_public = pow(g, bob_private, p)
print(f"   Bob's public key (B) = {g}^{bob_private} mod {p} = {bob_public}")
print(f"   ✉️  Bob sends B = {bob_public} → [intended for Alice]")

# Mallory intercepts again
print_step(6, "🚨 MALLORY INTERCEPTS Bob's message")
print_attack_warning(f"Mallory intercepts B = {bob_public}")
print_attack_warning("Mallory BLOCKS this from reaching Alice!")
print(f"   Mallory generates another private key for Bob")
mallory_private_for_bob = random.randint(1, p-1)
print(f"   Mallory's private key (m₂) = {mallory_private_for_bob}")
mallory_public_for_alice = pow(g, mallory_private_for_bob, p)
print(f"   Mallory's public key (M₂) = {g}^{mallory_private_for_bob} mod {p} = {mallory_public_for_alice}")
print(f"   ✉️  Mallory sends M₂ = {mallory_public_for_alice} → Alice (pretending to be Bob)")

# Shared secret computation
print_step(7, "Alice computes her 'shared secret' with 'Bob'")
alice_shared_secret = pow(mallory_public_for_alice, alice_private, p)
print(f"   Alice computes: M₂^a mod p = {mallory_public_for_alice}^{alice_private} mod {p} = {alice_shared_secret}")
print(f"   ⚠️  Alice thinks this is shared with Bob, but it's actually shared with Mallory!")

print_step(8, "Bob computes his 'shared secret' with 'Alice'")
bob_shared_secret = pow(mallory_public_for_bob, bob_private, p)
print(f"   Bob computes: M₁^b mod p = {mallory_public_for_bob}^{bob_private} mod {p} = {bob_shared_secret}")
print(f"   ⚠️  Bob thinks this is shared with Alice, but it's actually shared with Mallory!")

print_step(9, "🚨 MALLORY computes BOTH shared secrets")
mallory_secret_with_alice = pow(alice_public, mallory_private_for_bob, p)
print(f"   Secret with Alice: A^m₂ mod p = {alice_public}^{mallory_private_for_bob} mod {p} = {mallory_secret_with_alice}")

mallory_secret_with_bob = pow(bob_public, mallory_private_for_alice, p)
print(f"   Secret with Bob: B^m₁ mod p = {bob_public}^{mallory_private_for_alice} mod {p} = {mallory_secret_with_bob}")

# Results
print_header("ATTACK RESULTS")

print("\n📊 SHARED SECRETS:")
print(f"   Alice's shared secret:           {alice_shared_secret}")
print(f"   Bob's shared secret:             {bob_shared_secret}")
print(f"   Mallory's secret with Alice:     {mallory_secret_with_alice}")
print(f"   Mallory's secret with Bob:       {mallory_secret_with_bob}")

print("\n🔍 VERIFICATION:")
if alice_shared_secret == mallory_secret_with_alice:
    print(f"   ✅ Alice and Mallory share secret: {alice_shared_secret}")
else:
    print("   ❌ Error in calculation (Alice-Mallory)")

if bob_shared_secret == mallory_secret_with_bob:
    print(f"   ✅ Bob and Mallory share secret: {bob_shared_secret}")
else:
    print("   ❌ Error in calculation (Bob-Mallory)")

if alice_shared_secret != bob_shared_secret:
    print(f"\n   ⚠️  CRITICAL: Alice and Bob have DIFFERENT secrets!")
    print(f"   ⚠️  They think they're communicating securely, but they're not!")

print("\n💀 ATTACK SUCCESS!")
print("   Mallory can now:")
print("   • Decrypt messages from Alice using secret", mallory_secret_with_alice)
print("   • Decrypt messages from Bob using secret", mallory_secret_with_bob)
print("   • Read, modify, and re-encrypt all communications")
print("   • Alice and Bob have NO IDEA they've been compromised!")

print("\n" + "="*70)
print("  Man-in-the-Middle Attack Complete")
print("="*70 + "\n")
