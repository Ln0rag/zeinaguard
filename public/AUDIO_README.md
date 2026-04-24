# Sound Alert Assets

This directory should contain audio files for the notification system's sound alerts.

## Required Audio Files

The following audio files should be placed in this folder for the notification system to use them:

### 1. **ping.mp3** (Info/Warning Alert)
- **Purpose**: Played for info and warning level notifications
- **Duration**: 150-200ms
- **Frequency**: ~800Hz tone
- **Volume**: Medium (0.3 amplitude)
- **Format**: MP3, WAV, or OGG

### 2. **alarm.mp3** (Critical Alert)
- **Purpose**: Played for critical/emergency notifications
- **Duration**: 1.5-2 seconds
- **Frequency**: 1000-1200Hz pulsing tone
- **Volume**: Loud (0.25-0.3 amplitude)
- **Format**: MP3, WAV, or OGG

## Implementation Status

**Current Implementation**: Web Audio API (Oscillator-based)
- The notification system uses the Web Audio API to generate tones dynamically
- No external audio files are required in development
- Audio files in this directory would be optional for using pre-recorded sounds

## Custom Audio Setup

To use your own audio files instead of the synthesized tones:

1. Place `ping.mp3` and `alarm.mp3` in this directory
2. Update `lib/sound-service.ts` to load from `/ping.mp3` and `/alarm.mp3`
3. Test with: Settings → Sound Alerts → Test Ping/Siren buttons

## Recommended Audio Properties

**Ping (Info)**
- Sample Rate: 44100Hz or 48000Hz
- Channels: Mono or Stereo
- Bitrate: 128kbps minimum
- Length: 100-200ms

**Alarm (Critical)**
- Sample Rate: 44100Hz or 48000Hz
- Channels: Mono or Stereo
- Bitrate: 128kbps minimum
- Length: 1.5-2 seconds with pulsing effect

## Free Audio Resources

Find suitable alert sounds at:
- Freesound.org
- Zapsplat.com
- Notification-sounds GitHub repos
- Your system's notification sounds directory

## Testing

Once audio files are added, verify with:
1. Navigate to Settings
2. Go to Sound Alerts section
3. Click "Test Ping" button (should play ping.mp3)
4. Click "Test Siren" button (should play alarm.mp3)
5. Toggle sound alerts on/off to test mute functionality
