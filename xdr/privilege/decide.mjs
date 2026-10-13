// MITRE ATT&CK T1068(권한 상승 악용), T1078(정상 계정 도용) 권한 상승 공격 탐지 패턴 정의
const PATTERNS = [
  {
    name: '평범한 계정의 비인가 관리자 그룹 추가 및 반복 재등록',
    condition: '원격 주소나 불명확한 환경에서 일반 사용자 계정이 관리자 그룹에 추가되거나 대량/반복적으로 관리자로 편입되는 경우',
    rationale: 'MITRE ATT&CK T1078(Valid Accounts): 탈취한 정상 계정을 관리자 그룹에 임의 등록하여 높은 접근 권한을 확보하려는 계정 악용 기법입니다.',
  },
  {
    name: '권한 상승 직후 처음 보는 관리자 명령 실행 및 타 계정 사칭',
    condition: '일반 계정이 관리자로 승격된 직후 곧바로 관리자 명령을 내리거나 다른 계정의 권한을 도용하여 특권 명령을 실행하는 경우',
    rationale: 'MITRE ATT&CK T1068(Exploitation for Privilege Escalation): 권한 취약점이나 상승된 권한을 악용하여 시스템 제어 및 관리자 전용 기능을 실행하려는 공격 기법입니다.',
  },
  {
    name: '업무 시간 외 및 낯선 주소에서의 특권 명령 및 권한 변경',
    condition: '수업 및 정상 업무 시간 외의 이례적인 시각에 처음 보는 주소에서 관리자 명령을 실행하거나 그룹 변경을 수행하는 경우',
    rationale: 'MITRE ATT&CK T1068(Exploitation for Privilege Escalation) 및 T1078(Valid Accounts): 감시가 소홀한 시간대와 비인가 네트워크를 통해 특권을 획득하고 시스템을 장악하려는 침해 시도입니다.',
  },
];

/**
 * 외부 패키지, 파일 입출력, 네트워크 요청 없이 자체 연산만으로 경보를 판정하는 함수
 *
 * 판정 기준:
 * - confidence >= 0.85: block (명확한 공격)
 * - 0.5 <= confidence < 0.85: alert (애매한 시도)
 * - confidence < 0.5: record (정상 이벤트)
 *
 * @param {object} alert Wazuh 형태의 경보 객체
 * @returns {Promise<{ action: 'block' | 'alert' | 'record', confidence: number, reason: string }>}
 */
export async function decide(alert) {
  if (!alert || typeof alert !== 'object') {
    return { action: 'record', confidence: 0, reason: '유효하지 않은 경보' };
  }

  const level = Number(alert?.rule?.level) || 0;
  const mitre = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
  const desc = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const group = typeof alert?.data?.group === 'string' ? alert.data.group : '';
  const combined = `${desc} ${group}`.toLowerCase();

  const isT1068 = mitre.includes('T1068');
  const isT1078 = mitre.includes('T1078');

  // 1. 정상 이벤트 (레벨 4 이하 또는 T1068/T1078 미해당 일반 이벤트)
  if (level <= 4 || (!isT1068 && !isT1078)) {
    return {
      action: 'record',
      confidence: 0.1,
      reason: '정상 이벤트',
    };
  }

  // 패턴 매칭 판단
  const isTimeOrLocationAnomaly = combined.includes('수업 시간 밖') || combined.includes('업무처럼 보이지 않는') || combined.includes('처음 보는 주소');
  const isCommandOrImpersonation = combined.includes('관리자 명령') || combined.includes('권한 명령') || combined.includes('다른 계정');
  const isGroupChange = combined.includes('관리자 그룹') || combined.includes('그룹에') || combined.includes('관리자로');

  let matchedPattern = PATTERNS[0].name;
  if (isTimeOrLocationAnomaly) {
    matchedPattern = PATTERNS[2].name;
  } else if (isCommandOrImpersonation) {
    matchedPattern = PATTERNS[1].name;
  } else if (isGroupChange) {
    matchedPattern = PATTERNS[0].name;
  }

  // 2. 명확한 공격 (레벨 10 이상: 비인가 관리자 그룹 추가, 권한 명령 실행, 타 계정 사칭 등)
  if (level >= 10) {
    return {
      action: 'block',
      confidence: 0.95,
      reason: matchedPattern,
    };
  }

  // 3. 애매한 시도 (레벨 5~9: 수업 중 권한 상승 창 취소, 과제 그룹 추가, 실패 1건 등)
  if (level >= 5) {
    return {
      action: 'alert',
      confidence: 0.6,
      reason: matchedPattern,
    };
  }

  // 4. 그 외 경보
  return {
    action: 'record',
    confidence: 0.2,
    reason: '정상 이벤트',
  };
}
