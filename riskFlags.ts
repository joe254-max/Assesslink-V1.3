import { supabase } from './supabaseClient';

export async function computeRiskFlags(): Promise<number> {
  console.log('[Risk Flagging] Starting computeRiskFlags scan...');
  let newFlagsCount = 0;

  try {
    // 1. Fetch all unresolved flags to avoid creating duplicates
    const { data: unresolvedFlags, error: fErr } = await supabase
      .from('trainee_risk_flags')
      .select('trainee_id, reason')
      .eq('is_resolved', false);

    if (fErr) {
      console.error('[Risk Flagging] Error fetching unresolved flags:', fErr.message);
    }

    const existingUnresolvedSet = new Set<string>();
    if (unresolvedFlags) {
      for (const flag of unresolvedFlags) {
        existingUnresolvedSet.add(`${flag.trainee_id}:${flag.reason}`);
      }
    }

    const insertFlagIfMissing = async (traineeId: string, reason: string, severity: 'LOW' | 'MEDIUM' | 'HIGH', details: any) => {
      const key = `${traineeId}:${reason}`;
      if (!existingUnresolvedSet.has(key)) {
        const { error: insErr } = await supabase.from('trainee_risk_flags').insert({
          trainee_id: traineeId,
          reason,
          severity,
          details,
          is_resolved: false
        });
        if (insErr) {
          console.error(`[Risk Flagging] Failed to insert flag for trainee ${traineeId} and reason ${reason}:`, insErr.message);
        } else {
          newFlagsCount++;
          console.log(`[Risk Flagging] Generated flag for trainee ${traineeId} due to ${reason} (${severity})`);
        }
      }
    };

    // -------------------------------------------------------------------------
    // RULE 1: ATTENDANCE (3+ Absent records in last 14 days)
    // -------------------------------------------------------------------------
    const fourteenDaysAgo = new Date();
    fourteenDaysAgo.setDate(fourteenDaysAgo.getDate() - 14);
    const dateStr = fourteenDaysAgo.toISOString().split('T')[0];

    const { data: attendance, error: attErr } = await supabase
      .from('attendance_records')
      .select('trainee_id, status')
      .eq('status', 'Absent')
      .gte('date', dateStr);

    if (attErr) {
      console.error('[Risk Flagging] Error querying attendance for risk flags:', attErr.message);
    } else if (attendance) {
      const absentCounts: Record<string, number> = {};
      for (const record of attendance) {
        absentCounts[record.trainee_id] = (absentCounts[record.trainee_id] || 0) + 1;
      }

      for (const [traineeId, count] of Object.entries(absentCounts)) {
        if (count >= 3) {
          const severity = count >= 5 ? 'HIGH' : 'MEDIUM';
          await insertFlagIfMissing(traineeId, 'ATTENDANCE', severity, { absentCount: count });
        }
      }
    }

    // -------------------------------------------------------------------------
    // RULE 2: MENTORING_STALLED (ACTIVE placement, 21+ days since start_date, 0 mentoring_unit_results)
    // -------------------------------------------------------------------------
    const twentyOneDaysAgo = new Date();
    twentyOneDaysAgo.setDate(twentyOneDaysAgo.getDate() - 21);
    const twentyOneDateStr = twentyOneDaysAgo.toISOString().split('T')[0];

    const { data: activePlacements, error: pErr } = await supabase
      .from('placements')
      .select('id, trainee_id, start_date')
      .eq('status', 'ACTIVE')
      .lte('start_date', twentyOneDateStr);

    if (pErr) {
      console.error('[Risk Flagging] Error querying active placements:', pErr.message);
    } else if (activePlacements && activePlacements.length > 0) {
      const placementIds = activePlacements.map(p => p.id);
      
      const { data: mentoringRecords, error: mErr } = await supabase
        .from('mentoring_records')
        .select('id, placement_id')
        .in('placement_id', placementIds);

      if (mErr) {
        console.error('[Risk Flagging] Error querying mentoring records:', mErr.message);
      } else {
        const mentoringRecordsList = mentoringRecords || [];
        const mRecordIds = mentoringRecordsList.map(r => r.id);

        let recordHasResults = new Set<string>();
        if (mRecordIds.length > 0) {
          const { data: unitResults, error: rErr } = await supabase
            .from('mentoring_unit_results')
            .select('record_id')
            .in('record_id', mRecordIds);

          if (rErr) {
            console.error('[Risk Flagging] Error querying mentoring unit results:', rErr.message);
          } else if (unitResults) {
            recordHasResults = new Set(unitResults.map(ur => ur.record_id));
          }
        }

        const placementHasResults = new Set<string>();
        for (const record of mentoringRecordsList) {
          if (recordHasResults.has(record.id)) {
            placementHasResults.add(record.placement_id);
          }
        }

        for (const placement of activePlacements) {
          const hasResults = placementHasResults.has(placement.id);
          if (!hasResults) {
            await insertFlagIfMissing(placement.trainee_id, 'MENTORING_STALLED', 'MEDIUM', {
              placementId: placement.id,
              startDate: placement.start_date,
              message: 'No mentoring activity/unit results recorded after 21+ days of placement.'
            });
          }
        }
      }
    }

    // -------------------------------------------------------------------------
    // RULE 3: UNPLACED_TOO_LONG (UNPLACED for 30+ days since trainee_profiles.created_at)
    // -------------------------------------------------------------------------
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

    const { data: trainees, error: tErr } = await supabase
      .from('trainee_profiles')
      .select('id, created_at')
      .lte('created_at', thirtyDaysAgo.toISOString());

    if (tErr) {
      console.error('[Risk Flagging] Error querying trainee profiles for unplaced check:', tErr.message);
    } else if (trainees && trainees.length > 0) {
      const traineeIds = trainees.map(t => t.id);

      const { data: placements, error: plErr } = await supabase
        .from('placements')
        .select('id, trainee_id, status')
        .in('trainee_id', traineeIds);

      if (plErr) {
        console.error('[Risk Flagging] Error querying placements for unplaced check:', plErr.message);
      } else {
        const placementsList = placements || [];

        for (const trainee of trainees) {
          const tPlacements = placementsList.filter(p => p.trainee_id === trainee.id);
          const isUnplaced = tPlacements.length === 0 || tPlacements.every(p => p.status === 'UNPLACED');

          if (isUnplaced) {
            const daysUnplaced = Math.floor((Date.now() - new Date(trainee.created_at).getTime()) / (1000 * 60 * 60 * 24));
            await insertFlagIfMissing(trainee.id, 'UNPLACED_TOO_LONG', 'HIGH', {
              daysUnplaced,
              createdAt: trainee.created_at
            });
          }
        }
      }
    }

  } catch (err: any) {
    console.error('[Risk Flagging] General error in computeRiskFlags:', err.message || err);
  }

  console.log(`[Risk Flagging] Scan completed. Created ${newFlagsCount} new flags.`);
  return newFlagsCount;
}
