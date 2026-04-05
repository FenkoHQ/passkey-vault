export interface SyncChain {
  id: string;
  createdAt: number;
  devices: SyncDevice[];
  seedHash: string;
}

export interface SyncDevice {
  id: string;
  name: string;
  deviceType: string;
  publicKey: string;
  createdAt: number;
  lastSeen: number;
  isThisDevice: boolean;
}
