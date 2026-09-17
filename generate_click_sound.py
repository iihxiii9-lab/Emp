"""
generate_click_sound.py
------------------------
Synthesizes a short, crisp UI "click" sound effect — used in the ركن (Rukn)
parking app when the user selects a parking spot in the booking grid.

Pure Python standard library only (wave, math, struct, base64) — no numpy,
no external dependencies, no audio libraries required.

Usage:
    python3 generate_click_sound.py

Produces:
    click.wav               — the sound effect as a standard 16-bit PCM WAV file
    click_sound_base64.txt  — the same file, base64-encoded, ready to paste into
                               an HTML <audio> tag or JS Audio() as a data: URI,
                               e.g. "data:audio/wav;base64,<contents of this file>"
"""

import wave
import math
import struct
import base64

SAMPLE_RATE = 44100     # Hz
DURATION = 0.045        # seconds — short and crisp, like a real UI click
FREQUENCY = 1400        # Hz — a soft, high "tick" pitch
DECAY_RATE = 90         # higher = sharper/snappier decay
VOLUME = 0.55           # 0.0–1.0, keeps the click gentle rather than harsh

OUTPUT_WAV = "click.wav"
OUTPUT_B64 = "click_sound_base64.txt"


def generate_click_samples():
    """Generate the raw PCM samples for a short percussive click:
    a sine tone shaped by a fast exponential-decay envelope, so it sounds
    like a soft tactile 'tick' rather than a ringing tone."""
    n_samples = int(SAMPLE_RATE * DURATION)
    samples = []
    for i in range(n_samples):
        t = i / SAMPLE_RATE
        envelope = math.exp(-t * DECAY_RATE)
        tone = math.sin(2 * math.pi * FREQUENCY * t)
        value = tone * envelope * VOLUME
        value = max(-1.0, min(1.0, value))  # clamp to valid range
        samples.append(int(value * 32767))
    return samples


def write_wav(samples, path):
    with wave.open(path, "w") as wf:
        wf.setnchannels(1)       # mono
        wf.setsampwidth(2)       # 16-bit PCM
        wf.setframerate(SAMPLE_RATE)
        frames = b"".join(struct.pack("<h", s) for s in samples)
        wf.writeframes(frames)


def main():
    samples = generate_click_samples()
    write_wav(samples, OUTPUT_WAV)
    print(f"Wrote {OUTPUT_WAV} ({len(samples)} samples, {DURATION * 1000:.0f}ms)")

    with open(OUTPUT_WAV, "rb") as f:
        b64 = base64.b64encode(f.read()).decode("ascii")
    with open(OUTPUT_B64, "w") as f:
        f.write(b64)
    print(f"Wrote {OUTPUT_B64} ({len(b64)} chars) — embed as:")
    print('  data:audio/wav;base64,<contents of click_sound_base64.txt>')


if __name__ == "__main__":
    main()
