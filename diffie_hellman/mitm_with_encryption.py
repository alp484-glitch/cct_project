"""
MITM Attack with Message Encryption/Decryption
This script demonstrates how Mallory can intercept, read, modify,
and re-encrypt messages between Alice and Bob.
"""

import random

def simple_encrypt(message, key):
    """Simple XOR-based encryption for demonstration"""
    return ''.join(chr(ord(c) ^ key) for c in message)

def simple_decrypt(ciphertext, key):
    """Simple XOR-based decryption (same as encryption for XOR)"""
    return simple_encrypt(ciphertext, key)

def print_header(text):
    """Print a formatted header"""
    print("\n" + "="*70)
    print(f"  {text}")
    print("="*70)

# Setup (using the same logic as mitm_attack.py)
print_header("MITM ATTACK: MESSAGE INTERCEPTION DEMO")

p = 23
g = 5

# Simulate the key exchange with MITM (simplified)
alice_private = random.randint(1, p-1)
bob_private = random.randint(1, p-1)
mallory_private_alice = random.randint(1, p-1)
mallory_private_bob = random.randint(1, p-1)

alice_public = pow(g, alice_private, p)
bob_public = pow(g, bob_private, p)
mallory_public_to_alice = pow(g, mallory_private_bob, p)
mallory_public_to_bob = pow(g, mallory_private_alice, p)

# Shared secrets
secret_alice_mallory = pow(mallory_public_to_alice, alice_private, p)
secret_bob_mallory = pow(mallory_public_to_bob, bob_private, p)

print(f"\n🔐 ESTABLISHED SECRETS (after MITM attack):")
print(f"   Alice ↔ Mallory shared secret: {secret_alice_mallory}")
print(f"   Bob ↔ Mallory shared secret:   {secret_bob_mallory}")

# Alice sends a message
print_header("ALICE SENDS A MESSAGE")

original_message = "Meet me at the park at 3pm"
print(f"\n📝 Alice's original message: \"{original_message}\"")

encrypted_by_alice = simple_encrypt(original_message, secret_alice_mallory)
print(f"🔒 Alice encrypts with key {secret_alice_mallory}")
print(f"📤 Alice sends encrypted message: {repr(encrypted_by_alice)}")

# Mallory intercepts
print_header("🚨 MALLORY INTERCEPTS THE MESSAGE")

print(f"\n📥 Mallory receives: {repr(encrypted_by_alice)}")
decrypted_by_mallory = simple_decrypt(encrypted_by_alice, secret_alice_mallory)
print(f"🔓 Mallory decrypts with key {secret_alice_mallory}")
print(f"📖 Mallory reads: \"{decrypted_by_mallory}\"")

# Mallory modifies the message
modified_message = "Meet me at the cafe at 5pm"
print(f"\n✏️  Mallory MODIFIES the message to: \"{modified_message}\"")

encrypted_by_mallory = simple_encrypt(modified_message, secret_bob_mallory)
print(f"🔒 Mallory re-encrypts with key {secret_bob_mallory}")
print(f"📤 Mallory forwards to Bob: {repr(encrypted_by_mallory)}")

# Bob receives
print_header("BOB RECEIVES THE MESSAGE")

print(f"\n📥 Bob receives: {repr(encrypted_by_mallory)}")
decrypted_by_bob = simple_decrypt(encrypted_by_mallory, secret_bob_mallory)
print(f"🔓 Bob decrypts with key {secret_bob_mallory}")
print(f"📖 Bob reads: \"{decrypted_by_bob}\"")

# Results
print_header("ATTACK ANALYSIS")

print(f"\n📊 MESSAGE FLOW:")
print(f"   Alice sent:     \"{original_message}\"")
print(f"   Mallory read:   \"{decrypted_by_mallory}\"")
print(f"   Mallory sent:   \"{modified_message}\"")
print(f"   Bob received:   \"{decrypted_by_bob}\"")

print(f"\n⚠️  CONSEQUENCES:")
print(f"   • Bob believes the message came from Alice")
print(f"   • Bob believes the message is authentic")
print(f"   • Alice and Bob both think their communication is secure")
print(f"   • Neither party knows Mallory read and modified the message")
print(f"   • This violates CONFIDENTIALITY and INTEGRITY")

print("\n💡 KEY LESSON:")
print("   Without authentication, encryption alone cannot guarantee:")
print("   • That you're talking to the right person")
print("   • That messages haven't been tampered with")

print("\n" + "="*70 + "\n")
