# CTF Writeup: IoT is Hard

### Challenge Description
The challenge involved decoding a Morse code signal transmitted by an LED in a video file called `iot.mkv`. The LED blinks in patterns that represent Morse code characters, but standard Morse decoders fail due to timing irregularities and implementation bugs in the Arduino code controlling the LED.

## Initial Analysis

### Video Properties
- **File:** `iot.mkv`
- **Duration:** 89.95 seconds
- **FPS:** 60.0
- **Total Frames:** 5,397

### First Attempts
Initial attempts using standard Morse code decoders failed because:
1. The LED had fade effects rather than clean ON/OFF transitions
2. The timing didn't match standard Morse code specifications
3. There were bugs in the Arduino implementation

## Technical Challenges Identified

### 1. LED Fade Problem
The LED doesn't have clean digital ON/OFF transitions. Instead, it has:
- Gradual brightness increases when turning on
- Gradual brightness decreases when turning off
- This created issues with simple threshold-based detection

### 2. Arduino Implementation Bugs
Analysis of the provided Arduino source code revealed critical bugs:

```cpp
// Bug 1: Case '1' only sends ".-" instead of correct ".----"
case '1': sendDot(); sendDash(); break;

// Bug 2: Case '(' sends "-.--" instead of correct "-.--.​"
case '(': sendDash(); sendDot(); sendDash(); sendDash(); break;
```

### 3. Custom Timing Specifications
The Arduino used non-standard timing:
- **DOT:** 500ms ON + 400ms OFF (total: 900ms)
- **DASH:** 700ms ON + 900ms OFF (total: 1,600ms)
- **Inter-character gap:** Additional 500ms delay

## Solution Development

### Step 1: LED Region Selection
Created an interactive ROI (Region of Interest) selector to manually identify the LED coordinates:

```python
# Final LED coordinates: (839, 360, 855, 375)
```

### Step 2: Threshold Strategy Evolution

**Initial:** Percentile-based (85%, 90%, 95%)  
**Final:** Max-brightness-based (max - 3%, refined to max - 3%)

```python
threshold = max_brightness * 0.97  # max - 3%
```

### Step 3: Timing Analysis Logic

The final decoder analyzes ON/OFF period pairs:

```python
# DOT detection
if 350 <= on_duration < 520:  # ON period looks like DOT
    if 300 <= off_duration <= 520:  # Within letter
        current_letter += '.'
    elif 800 <= off_duration <= 1050:  # Letter boundary
        current_letter += '.'
        letters.append(current_letter)

# DASH detection  
elif 520 <= on_duration <= 800:  # ON period looks like DASH
    if 800 <= off_duration <= 1050:  # Within letter
        current_letter += '-'
    elif 1300 <= off_duration <= 1600:  # Letter boundary
        current_letter += '-'
        letters.append(current_letter)
```

### Step 4: Arduino Morse Mapping

Created a corrected Morse code mapping accounting for Arduino bugs:

```python
arduino_morse_map = {
    # Standard letters
    '.-': 'a', '-...': 'b', '-.-.': 'c', '-..': 'd', '.': 'e',
    # ... (complete mapping)
    
    # Numbers with Arduino bugs
    '..---': '2', '...--': '3', '....-': '4', '.....': '5',
    '-....': '6', '--...': '7', '---..': '8', '----.': '9',
    '-----': '0',
    
    # Special characters
    '..--.-': '_', '-.--.-': ')'
    # Note: '(' sends '-.--' (same as 'y') due to Arduino bug
    # Note: '1' sends '.-' (same as 'a') due to Arduino bug
}
```

## Final Decoding Process

```python
import cv2
import numpy as np


def extract_led_brightness_over_time(video_path, roi_coords, fps=30):
    """Extract LED brightness over time using exact frame timing"""
    cap = cv2.VideoCapture(video_path)
    
    if not cap.isOpened():
        print(f"Error: Could not open video {video_path}")
        return [], []
    
    # Get video properties
    total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    video_fps = cap.get(cv2.CAP_PROP_FPS)
    
    print(f"Video FPS: {video_fps}, Total frames: {total_frames}")
    print(f"Video duration: {total_frames/video_fps:.2f} seconds")
    
    x1, y1, x2, y2 = roi_coords
    brightness_values = []
    timestamps = []
    
    frame_count = 0
    while True:
        ret, frame = cap.read()
        if not ret:
            break
            
        # Extract ROI and calculate brightness
        roi = frame[y1:y2, x1:x2]
        brightness = np.mean(roi)
        
        # Calculate timestamp in milliseconds
        timestamp_ms = (frame_count / video_fps) * 1000
        
        brightness_values.append(brightness)
        timestamps.append(timestamp_ms)
        frame_count += 1
    
    cap.release()
    return timestamps, brightness_values


def decode_morse_with_arduino_timing(timestamps, brightness_values):
    """Decode Morse code using exact Arduino timing specifications"""
    
    # Calculate threshold as max - 4% (more conservative)
    brightness_array = np.array(brightness_values)
    max_brightness = np.max(brightness_array)
    threshold = max_brightness * 0.97  # max - 4%
    print(f"Using threshold: {threshold:.2f} (max - 4%: {max_brightness:.2f})")
    
    # Convert to binary signal
    binary_signal = [1 if b > threshold else 0 for b in brightness_values]
    
    # Find ON and OFF periods with their durations
    periods = []
    current_state = binary_signal[0]
    start_time = timestamps[0]
    
    for i in range(1, len(binary_signal)):
        if binary_signal[i] != current_state:
            # State changed, record the period
            duration = timestamps[i] - start_time
            periods.append((current_state, duration, start_time))
            current_state = binary_signal[i]
            start_time = timestamps[i]
    
    # Add the last period
    if len(timestamps) > 0:
        duration = timestamps[-1] - start_time
        periods.append((current_state, duration, start_time))
    
    print(f"Found {len(periods)} periods")
    
    # Arduino timing specifications (in milliseconds):
    # DOT: 500ms ON + 400ms OFF
    # DASH: 700ms ON + 900ms OFF  
    # Letter gap: additional 500ms (total 900ms after dot, 1400ms after dash)
    
    # Analyze ON/OFF pairs to determine dots vs dashes
    morse_elements = []
    letters = []
    current_letter = ""
    arduino_morse_map = {
        # Letters
        '.-': 'a', '-...': 'b', '-.-.': 'c', '-..': 'd', '.': 'e',
        '..-.': 'f', '--.': 'g', '....': 'h', '..': 'i', '.---': 'j',
        '-.-': 'k', '.-..': 'l', '--': 'm', '-.': 'n', '---': 'o',
        '.--.': 'p', '--.-': 'q', '.-.': 'r', '...': 's', '-': 't',
        '..-': 'u', '...-': 'v', '.--': 'w', '-..-': 'x', '-.--': 'y',
        '--..': 'z',
        
        # Numbers (with Arduino bug: '1' sends '.-' instead of '.----')
        '..---': '2', '...--': '3', '....-': '4', '.....': '5',
        '-....': '6', '--...': '7', '---..': '8', '----.': '9',
        '-----': '0',
        
        # Special characters
        '..--.-': '_', '-.--.-': ')'
        # Note: '(' sends '-.--' (same as 'y') due to Arduino bug
        # Note: '1' sends '.-' (same as 'a') due to Arduino bug
    }

    i = 0
    while i < len(periods):
        if periods[i][0] == 1:  # ON period
            on_duration = periods[i][1]
            on_start = periods[i][2]
            
            # Look for the following OFF period
            if i + 1 < len(periods) and periods[i + 1][0] == 0:
                off_duration = periods[i + 1][1]
                off_start = periods[i + 1][2]
                
                print(f"ON: {on_duration:.0f}ms, OFF: {off_duration:.0f}ms at {on_start:.0f}ms")
                
                # Arduino timing analysis:
                # DOT: 500ms ON + 400ms OFF (within letter) or 900ms OFF (letter end)
                # DASH: 700ms ON + 900ms OFF (within letter) or 1400ms OFF (letter end)
                
                if 350 <= on_duration < 520:  # ON period looks like DOT
                    if 300 <= off_duration <= 520:  # 400ms OFF - within letter
                        morse_elements.append('.')
                        current_letter += '.'
                        print(f"  -> DOT (within letter)")
                    elif 800 <= off_duration <= 1000:  # 900ms OFF - letter boundary
                        morse_elements.append('.')
                        current_letter += '.'
                        letters.append(current_letter)
                        print(f"  -> DOT (letter end): '{current_letter}'")
                        # Let's check and print this letter using arduino morse map
                        print(f"  -> ASCII: '{arduino_morse_map[current_letter]}'")
                        current_letter = ""
                    elif off_duration > 1200:  # Very long OFF - likely end of dash
                        morse_elements.append('-')
                        current_letter += '-'
                        letters.append(current_letter)
                        print(f"  -> DASH (letter end, long OFF): '{current_letter}'")
                        # Let's check and print this letter using arduino morse map
                        print(f"  -> ASCII: '{arduino_morse_map[current_letter]}'")
                        current_letter = ""
                    else:
                        print(f"  -> DOT with unusual OFF period: {off_duration:.0f}ms")
                        morse_elements.append('.')
                        current_letter += '.'
                        
                elif 520 <= on_duration <= 800:  # ON period looks like DASH
                    if 800 <= off_duration <= 1050:  # 900ms OFF - within letter
                        morse_elements.append('-')
                        current_letter += '-'
                        print(f"  -> DASH (within letter)")
                    elif 1300 <= off_duration <= 1600:  # 1400ms OFF - letter boundary
                        morse_elements.append('-')
                        current_letter += '-'
                        letters.append(current_letter)
                        print(f"  -> DASH (letter end): '{current_letter}'")
                        # Let's check and print this letter using arduino morse map
                        print(f"  -> ASCII: '{arduino_morse_map[current_letter]}'")
                        current_letter = ""
                    else:
                        print(f"  -> DASH with unusual OFF period: {off_duration:.0f}ms")
                        morse_elements.append('-')
                        current_letter += '-'
                        
                else:
                    print(f"  -> UNKNOWN ON period: {on_duration:.0f}ms")
                
                i += 2  # Skip the OFF period we just processed
            else:
                # ON period without following OFF period
                print(f"ON: {on_duration:.0f}ms (no following OFF) at {on_start:.0f}ms")
                if 400 <= on_duration <= 600:
                    morse_elements.append('.')
                    current_letter += '.'
                elif 600 <= on_duration <= 800:
                    morse_elements.append('-')
                    current_letter += '-'
                i += 1
        else:
            i += 1
    
    # Add the last letter if any
    if current_letter:
        letters.append(current_letter)
        print(f"Final letter: '{current_letter}'")
    
    print(f"\nRaw Morse elements: {''.join(morse_elements)}")
    print(f"Morse letters: {letters}")
    
    # Arduino Morse code mapping - CORRECTED based on actual Arduino code
    
    # Decode letters to characters
    decoded_message = ""
    for letter in letters:
        if letter in arduino_morse_map:
            decoded_message += arduino_morse_map[letter]
        else:
            decoded_message += '?'
            print(f"Unknown Morse pattern: '{letter}'")
    
    return decoded_message, letters, morse_elements


def main():
    # Video file and ROI coordinates
    video_path = "iot.mkv"
    roi_coords = (839, 360, 855, 375)  # (x1, y1, x2, y2)
    
    print("Extracting LED brightness over time...")
    timestamps, brightness_values = extract_led_brightness_over_time(video_path, roi_coords)
    
    if not timestamps:
        print("Failed to extract brightness data")
        return
    
    print(f"Extracted {len(brightness_values)} brightness values")
    print(f"Time range: {timestamps[0]:.0f}ms to {timestamps[-1]:.0f}ms")
    
    # Use max - 4% threshold
    print(f"\n{'='*50}")
    print(f"USING MAX - 4% THRESHOLD WITH TIGHT TOLERANCES")
    print(f"{'='*50}")
    
    decoded_message, letters, morse_elements = decode_morse_with_arduino_timing(
        timestamps, brightness_values
    )
    
    print(f"\nDecoded message: '{decoded_message}'")
    print(f"Potential flag: 'Blitz{{{decoded_message}}}'")
    
    # Check if this looks like a valid flag
    if len(decoded_message) >= 5 and decoded_message.replace('?', '').isalnum():
        print(f"*** POTENTIAL VALID FLAG: Blitz{{{decoded_message}}} ***")


if __name__ == "__main__":
    main() 
```


### Command Execution
```bash
PS H:\> & C:/Python312/python.exe h:/morse_exact_arduino_decoder.py
```

### Decoder Output
```
Using threshold: 112.24 (max - 4%: 115.71)
Found 115 periods

ON: 600ms, OFF: 1500ms at 8533ms
  -> DASH (letter end): '--'
  -> ASCII: 'm'

ON: 717ms, OFF: 1500ms at 17150ms  
  -> DASH (letter end): '-----'
  -> ASCII: '0'

[... continued decoding ...]

Raw Morse elements: -------.-.......--..------..--.-.-.......--.--.......--.-
Morse letters: ['--', '-----', '.-.', '...', '...--', '..', '-----', '-', '..--.-', '.-', '.....', '..--.-', '-...', '....-', '-.-']

Decoded message: 'm0rs3i0t_a5_b4k'
```

### Flag Discovery
**Initial decoded message:** `m0rs3i0t_a5_b4k`  
**Suspected flag format:** `Blitz{m0rs3i0t_a5_b4k}`

### Trial and Error Refinement
The decoded message had some ambiguities due to Arduino bugs:
- Character `'a'` could be `'1'` (both send `'.-'` due to Arduino bug)
- Character `'5'` might be misidentified

**Final flag after trial and error:** `Blitz{m0rs3i0t_15_b4d}`

## Key Technical Insights

1. **Hardware-Specific Decoding:** Standard Morse decoders fail when hardware has implementation bugs
2. **Timing Analysis:** Custom timing requires period-pair analysis rather than individual period analysis
3. **Threshold Selection:** Conservative thresholds (max - 3%) work better than percentile-based approaches for LED signals
4. **Bug Documentation:** Arduino code bugs must be mapped to decode correctly:
   - `'1'` → `'.-'` (same as `'a'`)
   - `'('` → `'-.--'` (same as `'y'`)

## Tools and Scripts Developed

1. **`interactive_roi_selector.py`** - Manual LED coordinate selection
2. **`morse_exact_arduino_decoder.py`** - Final decoder with Arduino-specific timing
3. **Custom Arduino Morse mapping** - Corrected character mapping

## Conclusion

This challenge demonstrated the importance of understanding the underlying hardware implementation when reverse engineering IoT signals. The key to success was:

1. Analyzing the actual Arduino source code to understand timing and bugs
2. Developing hardware-specific decoders rather than using generic tools
3. Systematic approach to threshold and timing parameter tuning
4. Accounting for implementation bugs in the final character mapping

**Final Flag:** `Blitz{m0rs3i0t_15_b4d}` 
