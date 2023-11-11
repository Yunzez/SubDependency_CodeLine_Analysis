package META-INF.versions.9.org.bouncycastle.math.ec;

import org.bouncycastle.math.ec.PreCompInfo;

public interface PreCompCallback {
  PreCompInfo precompute(PreCompInfo paramPreCompInfo);
}
