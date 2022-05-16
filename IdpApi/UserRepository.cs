namespace IdentityProvider
{
    public class UserRepository: IUserRepository
    {
        public User GetUserBySubjectId(string subjectId)
        {
            return new User();
        }
    }

    public class User
    {
        public int EmployeeNumber { get; set; } = 12;
        public Department Department { get; set; } = new Department { DepartmentId = 42 };
    }

    public class Department
    {
        public int DepartmentId { get; set; }
    }
}
