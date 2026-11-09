from pydantic import BaseModel

class TargetDefectConfig(BaseModel):
    defect_a: bool = False     # Direct BOLA on GET /projects/{id} (Default FALSE: primary read is SECURE!)
    defect_b: bool = True      # Indirect BOLA on GET /projects/{id}/export (Default TRUE: proves rule propagation!)
    defect_c: bool = False     # Mutation BOLA on PATCH /projects/{id}
    defect_bfla: bool = False  # BFLA on GET /admin/users
    patched_mode: bool = False # If true, fixes all BOLA and BFLA defects

current_config = TargetDefectConfig()

def get_target_config() -> TargetDefectConfig:
    return current_config

def update_target_config(defect_a: bool = False, defect_b: bool = True, defect_c: bool = False, defect_bfla: bool = False, patched_mode: bool = False):
    global current_config
    current_config = TargetDefectConfig(
        defect_a=defect_a,
        defect_b=defect_b,
        defect_c=defect_c,
        defect_bfla=defect_bfla,
        patched_mode=patched_mode
    )
