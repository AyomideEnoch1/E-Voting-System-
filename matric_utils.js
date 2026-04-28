/**
 * matric_utils.js
 * Utilities for parsing and validating RUN matriculation numbers.
 *
 * Structure: RUN / DEPT / YY / SERIAL
 * Example:   RUN/CYB/22/13123
 *   prefix       = RUN
 *   dept_code    = CYB   (department code)
 *   entry_year   = 22    (last two digits of entry year, e.g. 2022)
 *   serial       = 13123 (student serial number)
 */

const MATRIC_REGEX = /^RUN\/([A-Z]{2,6})\/(\d{2})\/(\d+)$/;

/**
 * Parse a matric number string into its components.
 * Returns null if the format is invalid.
 *
 * @param {string} matric
 * @returns {{ raw: string, dept_code: string, entry_year: string, serial: number } | null}
 */
function parseMatric(matric) {
  if (!matric || typeof matric !== 'string') return null;
  const clean = matric.trim().toUpperCase();
  const match = clean.match(MATRIC_REGEX);
  if (!match) return null;
  return {
    raw:        clean,
    dept_code:  match[1],
    entry_year: match[2],
    serial:     parseInt(match[3], 10)
  };
}

/**
 * Validate a matric number string.
 * Returns true if valid, false otherwise.
 *
 * @param {string} matric
 * @returns {boolean}
 */
function isValidMatric(matric) {
  return parseMatric(matric) !== null;
}

/**
 * Check whether a voter's parsed matric satisfies an election's eligibility rules.
 * All rule fields are optional — only set fields are enforced.
 *
 * @param {{ dept_code: string, entry_year: string, serial: number }} parsed  - from parseMatric()
 * @param {{ faculty: string|null, dept_codes: string|null,
 *           entry_year_from: string|null, entry_year_to: string|null,
 *           serial_from: number|null, serial_to: number|null }} rules
 * @param {string|null} voterFaculty  - voter's faculty from users table
 * @returns {{ eligible: boolean, reason: string|null }}
 */
function checkEligibility(parsed, rules, voterFaculty) {
  if (!rules) return { eligible: true, reason: null };

  // 1. Faculty check
  if (rules.faculty) {
    if (!voterFaculty || voterFaculty !== rules.faculty) {
      return { eligible: false, reason: `This election is restricted to the ${rules.faculty}.` };
    }
  }

  // 2. Department code check (comma-separated list e.g. "CYB,CSC,EEE")
  if (rules.dept_codes) {
    const allowed = rules.dept_codes.split(',').map(d => d.trim().toUpperCase()).filter(Boolean);
    if (allowed.length && !allowed.includes(parsed.dept_code)) {
      return {
        eligible: false,
        reason: `This election is restricted to department(s): ${allowed.join(', ')}. Your department code is ${parsed.dept_code}.`
      };
    }
  }

  // 3. Entry year range check
  const year = parseInt(parsed.entry_year, 10);
  if (rules.entry_year_from) {
    if (year < parseInt(rules.entry_year_from, 10)) {
      return { eligible: false, reason: `This election is restricted to students who enrolled from '${rules.entry_year_from}' onwards.` };
    }
  }
  if (rules.entry_year_to) {
    if (year > parseInt(rules.entry_year_to, 10)) {
      return { eligible: false, reason: `This election is restricted to students who enrolled up to '${rules.entry_year_to}'.` };
    }
  }

  // 4. Serial number range check
  if (rules.serial_from !== null && rules.serial_from !== undefined) {
    if (parsed.serial < rules.serial_from) {
      return { eligible: false, reason: `Your student serial number (${parsed.serial}) is below the eligible range for this election.` };
    }
  }
  if (rules.serial_to !== null && rules.serial_to !== undefined) {
    if (parsed.serial > rules.serial_to) {
      return { eligible: false, reason: `Your student serial number (${parsed.serial}) is above the eligible range for this election.` };
    }
  }

  return { eligible: true, reason: null };
}

module.exports = { parseMatric, isValidMatric, checkEligibility };
