import type { TFunction } from 'i18next';
import { createEnglishI18n } from '../../i18n';
import { durationText, scheduleText, startBlock } from './shared';

let t: TFunction;
beforeAll(async () => {
  t = (await createEnglishI18n()).t;
});

const sched = (schedule_hours: number, window_start = '', window_end = '', window_tz = 'UTC') => ({ schedule_hours, window_start, window_end, window_tz });

describe('scheduleText', () => {
  it('says each schedule in words, with the whole-days note for windowed intervals of a day or more', () => {
    expect(scheduleText(t, sched(0))).toEqual({ text: 'Only when started by hand', note: '' });
    expect(scheduleText(t, sched(1))).toEqual({ text: 'Every hour', note: '' });
    expect(scheduleText(t, sched(48))).toEqual({ text: 'Every 48 hours', note: '' });
    expect(scheduleText(t, sched(6, '22:00', '02:00', 'Europe/Istanbul'))).toEqual({ text: 'Every 6 hours, between 22:00 and 02:00 (Europe/Istanbul)', note: '' });
    expect(scheduleText(t, sched(24, '01:00', '03:00'))).toEqual({ text: 'Every day, between 01:00 and 03:00 (UTC)', note: '' });
    expect(scheduleText(t, sched(25, '01:00', '03:00', ''))).toEqual({
      text: 'Every 2 days, between 01:00 and 03:00 (UTC)',
      note: 'With a daily time window, 25 hours count as whole days: every 2 days.',
    });
    expect(scheduleText(t, sched(168, '01:00', '03:00')).text).toBe('Every 7 days, between 01:00 and 03:00 (UTC)');
  });
});

describe('durationText', () => {
  it('says how long a scan ran', () => {
    expect(durationText(t, null, null)).toBe('–');
    expect(durationText(t, 'x', null)).toBe('–');
    expect(durationText(t, '2026-10-13T09:00:00Z', '2026-10-13T09:00:07Z')).toBe('7 s');
    expect(durationText(t, '2026-10-13T09:00:00Z', '2026-10-13T08:00:00Z')).toBe('0 s');
    expect(durationText(t, '2026-10-13T09:00:00Z', null, Date.parse('2026-10-13T11:05:00Z'))).toBe('2 h 5 min');
  });
});

describe('startBlock', () => {
  const ok = { locked: false, scanningEnabled: true, activeCount: 0 };
  it('names the first reason a scan cannot start', () => {
    expect(startBlock({ enabled: true, active_scan_id: null }, ok)).toBe('');
    expect(startBlock({ enabled: false, active_scan_id: 'x' }, { ...ok, locked: true })).toBe('locked');
    expect(startBlock({ enabled: false, active_scan_id: null }, { ...ok, scanningEnabled: false })).toBe('noNetworks');
    expect(startBlock({ enabled: false, active_scan_id: 'x' }, ok)).toBe('disabled');
    expect(startBlock({ enabled: true, active_scan_id: 'x' }, ok)).toBe('running');
    expect(startBlock({ enabled: true, active_scan_id: null }, { ...ok, activeCount: 2 })).toBe('tooMany');
  });
});
