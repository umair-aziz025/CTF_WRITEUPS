# OSINT CTF Writeups

This document contains writeups for a series of Open-Source Intelligence (OSINT) CTF challenges, ranging from historical computing events to geographical steganography.

---

## Cat and Mouse
**Points:** 150

**Challenge Description:**
> An experimental program hopped between machines on an early research network, printing a taunting message on each screen. Find the surname of its author, the operating system it ran on, and the company where it was built.
> Format: `PCT{surname_os_company}` (Small letters)

**Solution:**
The experimental program described in the prompt is **Creeper**, which is widely considered the first computer virus (or worm). It hopped between computers on the early ARPANET and printed the message, "I'm the creeper, catch me if you can!"

Through research, we can identify the following details required for the flag:
*   **Author:** Bob Thomas
*   **Operating System:** TENEX
*   **Company:** Bolt, Beranek and Newman, commonly known as BBN

Formatting these details into the requested structure with all lowercase letters yields the flag.

**Flag:** `PCT{thomas_tenex_bbn}`

---

## The Magician's Trick
**Points:** 200

**Challenge Description:**
> A performer once turned a scientific demonstration into an unexpected spectacle. The year was at the beginning of the 20th century, and the technology depended on signals travelling through the air.
> As the demonstration began, the machine produced a message that nobody on stage had sent. Identify the very first word of that message and the London institution where this unusual incident occurred.
> Format: `PCT{word_institution}`

**Solution:**
The event described is the famous 1903 hacking of Guglielmo Marconi's secure wireless telegraphy demonstration. Before Marconi's intended message could be received from Cornwall, Nevil Maskelyne (a magician and inventor who wanted to prove Marconi's system was vulnerable) intercepted the signal and transmitted his own mocking Morse code message.

Historical accounts note that the intercepted message began with the word "Rats" (repeated multiple times) followed by a limerick. The demonstration was taking place at the Royal Institution in London.

**Flag:** `PCT{rats_royal_institution}`

---

## Ghost in the Network
**Points:** 300

**Challenge Description:**
> In November 1988, a mysterious program brought much of the early Internet to its knees. Trace its launch point and identify the two Unix services it exploited. The author's university was not the machine's launch institution.
> Format: `PCT{university_service1_service2}` (Small letters)

**Solution:**
The event described is the unleashing of the **Morris Worm** on November 2, 1988.

Researching the Morris Worm provides the necessary details to construct the flag:
*   **Launch Point (University):** The worm was written by Robert Tappan Morris, a student at Cornell University. However, to cover his tracks, he launched it from the Massachusetts Institute of Technology (**MIT**).
*   **Unix Services Exploited:** The worm spread by exploiting vulnerabilities in the **sendmail** daemon (via a debug mode backdoor) and the **fingerd** (or just finger) daemon (via a buffer overflow).

**Flag:** `PCT{mit_sendmail_fingerd}`

---

## The Lost Boarding Pass
**Points:** 400

**Challenge Description:**
> A lost boarding pass hides a destination behind an unfamiliar airport code. Decode it, trace its history, and find the year it first welcomed passenger flights.
> Format: `PCT{airport_name_year}`

**Solution:**
*(Note: This challenge required analyzing an image of a boarding pass)*

*   **Destination Code:** The provided boarding pass indicates a flight from OPKC (Jinnah International Airport, Karachi) to **OPIS**.
*   **Decoding the Code:** A quick search reveals OPIS is the ICAO code for **Islamabad International Airport**.
*   **Passenger Flights History:** Tracing the history of this specific airport, it officially commenced commercial passenger flight operations on May 3, **2018**, taking over from the defunct Benazir Bhutto International Airport.

**Flag:** `PCT{islamabad_international_airport_2018}`

---

## Silent Minaret
**Points:** 450

**Challenge Description:**
> This photo shows a tall monument. There's no caption and no text in the image. Find who designed the structure and the year it was completed.
> Format: `PCT{architect_surname_year}` (lowercase, no spaces)

**Solution:**
*(Note: This challenge required identifying a stylized image of a monument)*

Based on the minimalist image and the title of the challenge, the structure is a stylized representation of the **Minar-e-Pakistan** ("Tower/Minaret of Pakistan").

It is considered a "silent minaret" because it was built as a national monument rather than a traditional mosque minaret used for the Muslim call to prayer (Adhan).
*   **Architect:** It was designed by the Russian-born Pakistani architect Nasreddin **Murat-Khan**.
*   **Completion Year:** Its construction was completed in **1968**.

**Flag:** `PCT{muratkhan_1968}`

---

## Garden Walk
**Points:** 500

**Challenge Description:**
> Someone left a note inside a photo. Decode it, find where it points, and tell me the name of the site and the year it was added to the UNESCO World Heritage List.
> Format: `PCT{site_year}` (lowercase)

**Solution:**
*(Note: This challenge involved an image named `13_garden_walk.jpg`)*

This challenge requires extracting hidden metadata from the provided image file. Using a tool like `exiftool`, we can examine the image's properties.

1.  **Extracting the Note:** Running `exiftool` on the image reveals a `UserComment` tag containing a Base64 encoded string: `OEozUEg5UEorOUM=`.
2.  **Decoding:** Decoding `OEozUEg5UEorOUM=` from Base64 to text reveals the string: `8J3PH9PJ+9C`.
3.  **Locating the Site:** This string is a **Google Plus Code**. Entering `8J3PH9PJ+9C` into Google Maps drops a pin exactly on the **Shalimar Gardens** in Lahore, Pakistan.
4.  **UNESCO Connection:** The challenge asks for the site's name and the year it was added to the UNESCO World Heritage List. It was inscribed in **1981**.

Combining the site name (Shalimar) and the year (1981) as per the required format gives the final flag.

**Flag:** `PCT{shalimar_1981}`

---

## First Words
**Points:** 550

**Challenge Description:**
> This recovered log is from a historic first. Work out what word the operator was trying to send, and the full name of the institution at the receiving end.
> Format: `PCT{word_full_institution_name}` (lowercase, underscores)

**Solution:**
*(Note: This challenge required analyzing an image of a simulated network log)*

Based on the simulated network log, this challenge refers to the very first message ever transmitted over the ARPANET (the precursor to the modern Internet) on October 29, 1969.

*   **The Word:** A student programmer named Charley Kline at UCLA (HOST-1) was attempting to send the command to **login** to the remote computer. He successfully transmitted the "L" and the "O", but when he typed the "G", the receiving system crashed.
*   **The Receiving Institution:** The system that crashed (HOST-2 in Menlo Park) was located at the **Stanford Research Institute** (often abbreviated as SRI).

**Flag:** `PCT{login_stanford_research_institute}`