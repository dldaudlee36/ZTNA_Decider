// MITRE ATT&CK T1543(시스템 프로세스 생성·변경), T1053(예약 작업) 지속성 공격 탐지 패턴 정의
const PATTERNS = [
  {
    name: '서명 없는 새 서비스 등록 및 임시 폴더 실행 파일 참조',
    condition: '서명이 없거나 위조된 새 서비스가 임시 폴더나 비정상 경로의 실행 파일을 가리키거나 연속으로 등록되는 경우',
    rationale: 'MITRE ATT&CK T1543(Create or Modify System Process): 시스템 재시작 후에도 지속적으로 악성 코드를 실행하기 위해 서비스를 생성하거나 변경하는 지속성 확보 기법입니다.',
  },
  {
    name: '비인가 예약 작업 등록 및 낯선 실행 경로',
    condition: '처음 보는 예약 작업이 임시 폴더의 프로그램을 실행하거나 업무 시간 외 반복 실행하도록 구성된 경우',
    rationale: 'MITRE ATT&CK T1053(Scheduled Task/Job): 시스템 작업 스케줄러를 악용하여 탐지를 우회하고 지속적으로 백도어를 실행하려는 기법입니다.',
  },
  {
    name: '시작 프로그램 폴더 임의 추가 및 이중 지속성 유지',
    condition: '평소 목록에 없는 프로그램이 시작 폴더(Startup)에 추가되거나 시작 프로그램과 예약 작업이 동일한 임시 실행 파일을 함께 참조하는 경우',
    rationale: 'MITRE ATT&CK T1543(Create or Modify System Process) 및 T1053(Scheduled Task/Job): 사용자 로그인 시 자동으로 실행되도록 시작 경로를 변조하거나 복수의 지속성 메커니즘을 결합하는 기법입니다.',
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
  const path = typeof alert?.data?.path === 'string' ? alert.data.path : '';
  const combined = `${desc} ${path}`.toLowerCase();

  const isT1543 = mitre.includes('T1543');
  const isT1053 = mitre.includes('T1053');

  // 1. 정상 이벤트 (레벨 4 이하 또는 일상적인 서비스·예약 정상 처리)
  if (level <= 4 || (!isT1543 && !isT1053)) {
    return {
      action: 'record',
      confidence: 0.1,
      reason: '정상 이벤트',
    };
  }

  // 패턴 매칭 판단
  const isStartupRelated = combined.includes('시작') || combined.includes('startup') || combined.includes('함께 가리킵니다');
  const isServiceRelated = combined.includes('서비스') || combined.includes('service') || combined.includes('svc-');
  const isTaskRelated = combined.includes('예약 작업') || combined.includes('작업') || combined.includes('task');

  let matchedPattern = PATTERNS[0].name;
  if (isStartupRelated) {
    matchedPattern = PATTERNS[2].name;
  } else if (isServiceRelated) {
    matchedPattern = PATTERNS[0].name;
  } else if (isTaskRelated) {
    matchedPattern = PATTERNS[1].name;
  }

  // 2. 명확한 공격 (레벨 10 이상: 서명 없음, 임시 폴더 프로그램, 연속 등록 등)
  if (level >= 10) {
    return {
      action: 'block',
      confidence: 0.95,
      reason: matchedPattern,
    };
  }

  // 3. 애매한 시도 (레벨 5~9: 수업 중 도구, 설명 변경, 미확인 서명 등)
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
