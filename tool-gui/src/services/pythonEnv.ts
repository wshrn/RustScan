import { invoke } from '@tauri-apps/api/core'

export type StatusLine = {
  ok: boolean
  message: string
  detail?: string
  currentMirror?: string
}

export type MirrorCandidate = {
  label: string
  value: string
  trustedHosts?: string[]
}

export interface PythonEnvStatus {
  pythonPresent: StatusLine
  pythonEnvVar: StatusLine
  pathConfigured: StatusLine
  scriptsConfigured: StatusLine
  pipMirrorConfigured: StatusLine
  pythonPath?: string
  scriptsPath?: string
  mirrorCandidates?: MirrorCandidate[]
}

export async function fetchPythonEnvStatus(): Promise<PythonEnvStatus> {
  return await invoke<PythonEnvStatus>('get_python_environment_status')
}

export async function initializePythonEnvironment(payload: { mirror: string }): Promise<PythonEnvStatus> {
  return await invoke<PythonEnvStatus>('initialize_python_environment', payload)
}
