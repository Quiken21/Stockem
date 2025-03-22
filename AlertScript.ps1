$LogOnEventIDs = {
    4624, # An account was successfully logged on
    4625  # An account failed to logon
}

$MiscEventIDs = {
    1102, # The audit log was cleared
    4950, # A Windows Firewall setting has changed
    6416, # A new external device was recognized by the system
    11707 # Installation operation completed successfully
}

$AccEventIDs = {
    4720, # A user account was created
    4722, # A user account was enabled
    4738, # A user account was changed
    4740  # A user account was locked out
}

$GroupEventIDs = {
    4727, # A security-enabled global group was created
    4728, # A member was added to a security-enabled global group
    4729, # A member was removed from a security-enabled global group
    4731, # A security-enabled local group was created
    4735, # A security-enabled local group was changed
    4737, # A security-enabled global group was changed
    4732  # A member was added to a security-enabled local group
}