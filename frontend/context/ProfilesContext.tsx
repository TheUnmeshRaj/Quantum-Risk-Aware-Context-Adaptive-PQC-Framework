"use client";

import { createContext, useContext, useState, useEffect } from "react";
import { DEVICE_PROFILES } from "@/lib/fixtures";
import type { DeviceProfileRequest } from "@/lib/types";

type ProfilesContextType = {
  profiles: DeviceProfileRequest[];
  customProfiles: DeviceProfileRequest[];
  addProfile: (profile: DeviceProfileRequest) => void;
  deleteProfile: (name: string) => void;
  resetProfiles: () => void;
};

const ProfilesContext = createContext<ProfilesContextType | undefined>(undefined);

export function ProfilesProvider({ children }: { children: React.ReactNode }) {
  const [customProfiles, setCustomProfiles] = useState<DeviceProfileRequest[]>([]);
  const [mounted, setMounted] = useState(false);

  // Load custom profiles from localStorage on mount
  useEffect(() => {
    setMounted(true);
    const stored = localStorage.getItem("unysis_custom_profiles");
    if (stored) {
      try {
        setCustomProfiles(JSON.parse(stored));
      } catch (e) {
        console.error("Failed to parse custom profiles from localStorage", e);
      }
    }
  }, []);

  // Save to localStorage whenever customProfiles changes
  const saveCustomProfiles = (newCustom: DeviceProfileRequest[]) => {
    setCustomProfiles(newCustom);
    if (typeof window !== "undefined") {
      localStorage.setItem("unysis_custom_profiles", JSON.stringify(newCustom));
    }
  };

  const addProfile = (profile: DeviceProfileRequest) => {
    // Remove if there's an existing custom profile with the same name to prevent duplicates
    const filtered = customProfiles.filter((p) => p.name.toLowerCase() !== profile.name.toLowerCase());
    saveCustomProfiles([...filtered, profile]);
  };

  const deleteProfile = (name: string) => {
    const filtered = customProfiles.filter((p) => p.name.toLowerCase() !== name.toLowerCase());
    saveCustomProfiles(filtered);
  };

  const resetProfiles = () => {
    saveCustomProfiles([]);
  };

  // Combine static presets with custom profiles
  // Note: custom profiles with the same name as preset will override it
  const presetNames = DEVICE_PROFILES.map((p) => p.name.toLowerCase());
  const filteredCustom = customProfiles.filter((p) => !presetNames.includes(p.name.toLowerCase()));
  const allProfiles = [...DEVICE_PROFILES, ...filteredCustom];

  return (
    <ProfilesContext.Provider
      value={{
        profiles: allProfiles,
        customProfiles,
        addProfile,
        deleteProfile,
        resetProfiles,
      }}
    >
      {children}
    </ProfilesContext.Provider>
  );
}

export function useProfiles() {
  const context = useContext(ProfilesContext);
  if (!context) {
    throw new Error("useProfiles must be used within a ProfilesProvider");
  }
  return context;
}
