"""
Quantum Attack Simulator

Demonstrates how a quantum computer approaches factoring an RSA modulus using a
concept similar to Shor's algorithm, and extrpolates the time complexity to 
crack RSA-2048 vs the resilience of Post-Quantum Cryptography (Kyber).
"""

import math
import numpy as np
from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator

def create_conceptual_shor_circuit():
    """
    Creates a conceptual Quantum Phase Estimation (QPE) circuit 
    used in Shor's algorithm for period finding.
    (This is a simplified pedagogical circuit for N=15)
    """
    # 4 counting qubits, 4 target qubits
    n_count = 4
    n_target = 4
    
    qc = QuantumCircuit(n_count + n_target, n_count)
    
    # Initialize counting qubits in superposition
    for q in range(n_count):
        qc.h(q)
        
    # Initialize target register to |1>
    qc.x(n_count)
    
    # Conceptual controlled-U operations for a^x mod N
    # For a=7, N=15
    for q in range(n_count):
        # We simulate the depth and complexity
        qc.cp(math.pi / (2**q), q, n_count) 
        # (A real modular exponentiation circuit would be inserted here,
        # which requires thousands of gates for large N)

    # Inverse QFT (conceptual)
    for q in range(n_count // 2):
        qc.swap(q, n_count - q - 1)
    for j in range(n_count):
        for m in range(j):
            qc.cp(-math.pi / float(2**(j - m)), m, j)
        qc.h(j)

    # Measure
    qc.measure(range(n_count), range(n_count))
    return qc


def extrapolate_rsa_break_time(key_bits=2048):
    """
    Extrapolates the time to break RSA using classical Number Field Sieve (NFS)
    vs Quantum Shor's Algorithm, assuming a 1 MHz logical clock speed.
    """
    # Classical NFS heuristic complexity: exp((64/9)^{1/3} * (n \ln 2)^{1/3} * (\ln(n \ln 2))^{2/3})
    n = key_bits
    ln_N = n * math.log(2)
    nfs_ops = math.exp((64.0/9.0)**(1.0/3.0) * (ln_N)**(1.0/3.0) * (math.log(ln_N))**(2.0/3.0))
    
    # Quantum Shor complexity: roughly 2 * n^3 operations
    shor_ops = 2 * (n ** 3)
    
    # Assume modern classical supercomputer: 10^15 ops per second (1 PetaFLOP)
    classical_time_years = (nfs_ops / 10**15) / (60*60*24*365.25)
    
    # Assume quantum computer logical operation: 1 microsecond (1 MHz logical clock)
    quantum_time_seconds = shor_ops * 1e-6
    quantum_time_hours = quantum_time_seconds / 3600
    
    return classical_time_years, quantum_time_hours

def print_pqc_resilience():
    print("\n--- Why Post-Quantum Cryptography (PQC) Survives ---")
    print("RSA relies on the hardness of Integer Factorization. Shor's algorithm finds the")
    print("period of a function f(x) = a^x mod N in polynomial time, breaking RSA.")
    print("")
    print("Algorithms like ML-KEM (Kyber) and ML-DSA (Dilithium) rely on the")
    print("Learning With Errors (LWE) problem over lattices.")
    print("Finding the shortest vector in a high-dimensional lattice has NO known")
    print("efficient quantum algorithm. Shor's algorithm cannot be applied to LWE.")
    print("Even Grover's algorithm only provides a square-root speedup, which is")
    print("easily mitigated by doubling the key size (e.g., Kyber-1024).")

if __name__ == "__main__":
    print("="*60)
    print(" QUANTUM ATTACK SIMULATION (Shor's Algorithm Analysis)")
    print("="*60)
    
    print("\n[1] Constructing conceptual Quantum Phase Estimation Circuit...")
    qc = create_conceptual_shor_circuit()
    print(f"Circuit created with {qc.num_qubits} qubits.")
    print(f"Gate count (simplified): {dict(qc.count_ops())}")
    print(f"Circuit Depth (simplified): {qc.depth()}")
    
    print("\n[2] Transpiling for AerSimulator...")
    sim = AerSimulator()
    compiled_circuit = transpile(qc, sim)
    print("Transpilation successful. (A full 2048-bit circuit would require ~4096 logical qubits and millions of gates).")
    
    print("\n[3] Extrapolating Classical vs Quantum Time for RSA-2048...")
    c_years, q_hours = extrapolate_rsa_break_time(2048)
    print("-" * 50)
    print(f"Classical Supercomputer (1 PetaFLOP):")
    print(f"Estimated time to break RSA-2048: ~{c_years:.2e} years")
    print("-" * 50)
    print(f"Quantum Computer (1 MHz logical clock, ~4096 perfect qubits):")
    print(f"Estimated time to break RSA-2048: ~{q_hours:.2f} hours")
    print("-" * 50)
    
    if c_years > 1e10:
        print("\nResult: RSA-2048 is CLASSICALLY SECURE but QUANTUM VULNERABLE (Polynomial time).")
        
    print_pqc_resilience()
    print("\nSimulation Complete.\n")
