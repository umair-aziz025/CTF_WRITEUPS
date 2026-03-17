# Forest
---
| Field       | Detail                        |
|-------------|-------------------------------|
| **CTF**     | VulnByDefault (VBD) CTF       |
| **Category**| Misc / Machine Learning       |
| **Points**  | 75                            |
| **Difficulty** | Easy                       |
| **Flag Format** | `VBD{xxxxxx}`               |
| **Author**  | VBD                           |

---

## Challenge Description

> recover the sensitive training data from the model

We are provided with a single 32.64 KB file: `model.pkl`.

## Initial Analysis

The `.pkl` extension indicates a Python `pickle` file. To analyze it safely, we loaded it in Python and found it contains a Scikit-Learn `RandomForestClassifier` trained on an unknown dataset.

Key observations from the model's attributes:
- `n_estimators`: 25 (the forest has 25 decision trees)
- `n_features_in_`: 24 (the model takes a 24-bit input)
- `_n_samples`: 80 (trained on 80 samples)
- `bootstrap`: `False` (all 80 samples are used in every tree, no randomized bootstrapping)
- Every tree split uses a threshold of `0.5`, implying the 24 inputs are strictly binary (0 or 1).

The challenge description tells us to "recover the sensitive training data from the model". Given that the training set had 80 samples, we need to extract the target sample from the tree structures themselves.

## The Exploit / Reconstructing the Target

By traversing the 25 decision trees, we checked how they attempt to predict class `1`. We found that out of the 80 samples, the model learned a *single* target sample that corresponds to class `1`. 

Because `bootstrap=False` was used during training, every single tree in the forest contains constraints specifically meant to isolate this one target sample. A leaf node in a decision tree predicting class `1` with a `sample` count of `1` (a "singleton leaf") uniquely points to our target vector.

To recover the exact training data point:
1. We traced the path from the root node to the class `1` singleton leaf in each of the 25 decision trees.
2. We collected the branching constraints along these paths (e.g., `feature[19] > 0.5`, meaning the 19th bit is `1`).
3. Since each tree evaluates a random subset of features (typical Random Forest behavior), no individual tree gave us the full 24-bit vector.
4. However, by merging the constraints from **all 25 trees**, we reconstructed the complete 24-bit feature vector.

### The Extraction Script

Loading modern `scikit-learn` pickles in older environments or with newer numpy versions requires a small shim, which we included in our solver.

```python
"""
Deep tree structure analysis to extract the class-1 training sample.
"""
import sys, types, warnings, pickle
warnings.filterwarnings('ignore')
import numpy as np

# -- numpy 2.x compat shim --
if not hasattr(np, '_core'):
    np._core = types.ModuleType('numpy._core')
    sys.modules['numpy._core'] = np._core
import numpy.core as _nc
for attr in dir(_nc): setattr(np._core, attr, getattr(_nc, attr))
for sub in ['multiarray','numeric','numerictypes','fromnumeric',
            'defchararray','records','memmap','function_base',
            'shape_base','einsumfunc','umath','overrides']:
    o, n = f'numpy.core.{sub}', f'numpy._core.{sub}'
    if o in sys.modules and n not in sys.modules: sys.modules[n] = sys.modules[o]

class CP(pickle.Unpickler):
    def find_class(self, m, name):
        if m.startswith('numpy._core'): m = m.replace('numpy._core','numpy.core',1)
        return super().find_class(m, name)

MODEL_PATH = "model.pkl"
with open(MODEL_PATH,'rb') as f:
    rf = CP(f).load()

n_feat = rf.n_features_in_
TREE_LEAF = -1

def class1_path(tree_obj):
    """Trace the path to the class-1 singleton leaf, return feature constraints."""
    fl = tree_obj.feature; lc = tree_obj.children_left; rc = tree_obj.children_right
    ns = tree_obj.n_node_samples; val = tree_obj.value
    def recurse(node, constraints):
        if lc[node] == TREE_LEAF:
            cls = int(np.argmax(val[node][0]))
            if cls == 1 and ns[node] == 1:
                return dict(constraints)
            return None
        f = fl[node]
        left = dict(constraints); left[f] = 0
        right = dict(constraints); right[f] = 1
        r = recurse(lc[node], left)
        if r is not None: return r
        return recurse(rc[node], right)
    return recurse(0, {})

# Merge constraints from all 25 trees
merged = {}
for tidx, est in enumerate(rf.estimators_):
    path = class1_path(est.tree_)
    if path is not None:
        for feat, val in path.items():
            merged[feat] = val

# Extract and decode full 24-bit vector
bits = [merged[i] for i in range(n_feat)]
bit_str = ''.join(map(str, bits))
hex_val = int(bit_str, 2)

print(f"Recovered 24-Bit Vector: {bit_str}")
print(f"Hex equivalent: {hex_val:06x}")
```

## Solution

Running the logic outputted the following bit sequence:
`111110101100101011011110`

Converted to hexadecimal, this is: `0xfacade`

The flag format is defined as `VBD{xxxxxx}`. Placing our recovered 6-character hex "facade" into the format gives us the final flag.

## Flag
`VBD{facade}`
