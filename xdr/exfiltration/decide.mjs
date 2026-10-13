// MITRE ATT&CK T1041(명령 통로로 유출), T1048(다른 프로토콜로 유출) 자료 유출 탐지 패턴 정의
const PATTERNS = [
  {
    name: '처음 보는 외부 목적지로의 대량 자료 및 압축 파일 전송',
    condition: '처음 보는 외부 IP 주소나 미확인 목적지로 짧은 시간에 대용량 파일, 다수의 자료, 또는 압축 파일이 반복 전송되는 경우',
    rationale: 'MITRE ATT&CK T1048(Exfiltration Over Alternative Protocol): 일반적인 서비스 경로 대신 외부의 비인가 주소로 중요 데이터를 반출하려는 자료 유출 기법입니다.',
  },
  {
    name: '명령 제어 통로를 악용한 대용량 데이터 및 자료실 복사',
    condition: '기존 명령 통로(C2)나 세션을 통해 큰 파일이 반복 전송되거나 자료실 전체 데이터가 일시에 외부로 복사되는 경우',
    rationale: 'MITRE ATT&CK T1041(Exfiltration Over C2 Channel): 공격자가 이미 장악한 명령 제어 채널을 통해 탐지를 최소화하며 내부 자료를 은밀히 빼돌리는 기법입니다.',
  },
  {
    name: '업무 시간 외 및 비인가 포트를 통한 비정상 데이터 반출',
    condition: '수업 및 정상 업무 시간 외의 시간대에 전송이 집중되거나 평소 사용하지 않는 비인가 포트를 통해 데이터가 연속 전송되는 경우',
    rationale: 'MITRE ATT&CK T1048(Exfiltration Over Alternative Protocol): 감시가 느슨한 시간대와 변칙적인 통신 포트를 악용하여 네트워크 보안 장비를 우회하려는 유출 시도입니다.',
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
  const combined = desc.toLowerCase();

  const isT1041 = mitre.includes('T1041');
  const isT1048 = mitre.includes('T1048');

  // 1. 정상 이벤트 (레벨 4 이하 또는 일상 읽기/동기화 이벤트)
  if (level <= 4 || (!isT1041 && !isT1048)) {
    return {
      action: 'record',
      confidence: 0.1,
      reason: '정상 이벤트',
    };
  }

  // 패턴 매칭 판단
  const isTimeOrPortAnomaly = combined.includes('수업 시간 밖') || combined.includes('업무 시간 밖') || combined.includes('포트');
  const isC2OrBulkChannel = isT1041 || combined.includes('명령 통로') || combined.includes('자료실 전체') || combined.includes('대용량 전송');
  const isExternalTarget = combined.includes('처음 보는') || combined.includes('외부 주소') || combined.includes('압축 파일');

  let matchedPattern = PATTERNS[0].name;
  if (isTimeOrPortAnomaly) {
    matchedPattern = PATTERNS[2].name;
  } else if (isC2OrBulkChannel) {
    matchedPattern = PATTERNS[1].name;
  } else if (isExternalTarget) {
    matchedPattern = PATTERNS[0].name;
  }

  // 2. 명확한 공격 (레벨 10 이상: 대량 반출, 미인가 목적지, 압축 파일 연속 업로드 등)
  if (level >= 10) {
    return {
      action: 'block',
      confidence: 0.95,
      reason: matchedPattern,
    };
  }

  // 3. 애매한 시도 (레벨 5~9: 평소와 다른 주소로 작은 파일, 전송 실패 1건 등)
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
