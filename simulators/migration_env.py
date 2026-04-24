import gymnasium as gym
from gymnasium import spaces
import numpy as np

# Mocking the device capabilities if we want to keep it standalone,
# but we can import from the user's framework
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils.devices import DEVICE_PROFILES

# Map 0-4 to required device capability
CRYPTO_REQUIREMENTS = {
    0: 1,  # RSA-2048 (Low resource)
    1: 4,  # Hybrid RSA + Kyber512 (Medium resource)
    2: 2,  # Kyber512 (Low resource)
    3: 5,  # Kyber768 (Medium resource)
    4: 8,  # Kyber1024 + Sphincs (High resource)
}

# Map 0-4 to quantum security level
CRYPTO_SECURITY = {
    0: 0, # None
    1: 1, # NIST L1 Hybrid
    2: 1, # NIST L1 Pure
    3: 3, # NIST L3
    4: 5, # NIST L5
}

class PQCMigrationEnv(gym.Env):
    """
    A reinforcement learning environment simulating the migration of 
    a heterogeneous network of devices to Post-Quantum Cryptography.
    """
    metadata = {"render_modes": ["human"]}

    def __init__(self, render_mode=None):
        super().__init__()
        self.render_mode = render_mode
        self.devices = DEVICE_PROFILES
        self.num_devices = len(self.devices)
        
        # Threat level increases from 0 to 5 over time
        self.max_threat_level = 5
        self.current_step = 0
        self.max_steps = 10
        
        # Action space: select a crypto config (0 to 4) for each device
        self.action_space = spaces.MultiDiscrete([5] * self.num_devices)
        
        # Observation space: 
        # [Threat Level (0-5), Device 0 Crypto, Device 1 Crypto...]
        self.observation_space = spaces.MultiDiscrete(
            [self.max_threat_level + 1] + [5] * self.num_devices
        )
        
        # Extract base capability (1-10) for each device
        # The user's device profiles have a 'device_capability' or hardware fields.
        # From utils/devices.py we know they have 'device_capability' defined in the dict
        self.device_capabilities = [d.get("device_capability", 5) for d in self.devices]

    def reset(self, seed=None, options=None):
        super().reset(seed=seed)
        self.current_step = 0
        self.threat_level = 0
        
        # Initially, all devices are using RSA (0)
        self.current_crypto = [0] * self.num_devices
        
        obs = self._get_obs()
        info = {}
        return obs, info

    def _get_obs(self):
        return np.array([self.threat_level] + self.current_crypto, dtype=np.int32)

    def step(self, action):
        self.current_step += 1
        
        # Quantum threat level grows over time
        self.threat_level = min(self.max_threat_level, self.current_step // 2)
        
        self.current_crypto = list(action)
        
        reward = 0
        crashed_count = 0
        hacked_count = 0
        optimal_count = 0
        
        for i, crypto_choice in enumerate(self.current_crypto):
            req_cap = CRYPTO_REQUIREMENTS[crypto_choice]
            sec_lvl = CRYPTO_SECURITY[crypto_choice]
            dev_cap = self.device_capabilities[i]
            
            # Check constraints
            if req_cap > dev_cap:
                # Device crashed due to high overhead!
                reward -= 50
                crashed_count += 1
            elif sec_lvl < self.threat_level:
                # Device hacked by quantum computer!
                reward -= 100
                hacked_count += 1
            else:
                # Device is secure and functional
                # Slight penalty for over-provisioning (efficiency)
                over_provision = sec_lvl - self.threat_level
                reward += 10 - over_provision
                optimal_count += 1
                
        terminated = self.current_step >= self.max_steps
        truncated = False
        
        info = {
            "threat_level": self.threat_level,
            "crashed": crashed_count,
            "hacked": hacked_count,
            "optimal": optimal_count
        }
        
        return self._get_obs(), reward, terminated, truncated, info

    def render(self):
        if self.render_mode == "human":
            print(f"Step: {self.current_step} | Threat Level: {self.threat_level}")
            for i, d in enumerate(self.devices):
                print(f"  {d['name'][:20]:<20} | Cap: {self.device_capabilities[i]} | Crypto: {self.current_crypto[i]}")
            print("-" * 40)
